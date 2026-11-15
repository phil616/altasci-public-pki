package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/mail"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

const maxValidity = int64(397 * 24 * 60 * 60)

func dnsName(value string, wildcard bool) (string, error) {
	if value != strings.TrimSpace(value) {
		return "", errors.New("DNS whitespace is not allowed")
	}
	prefix := ""
	if wildcard && strings.HasPrefix(value, "*.") {
		prefix = "*."
		value = value[2:]
	}
	value, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	value = strings.ToLower(value)
	if err != nil || len(value) == 0 || len(prefix)+len(value) > 253 {
		return "", errors.New("invalid DNS name")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", errors.New("IP addresses must use IP SANs")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid DNS character")
			}
		}
	}
	return prefix + value, nil
}

func uriName(value string) (string, error) {
	if len(value) > 512 || strings.ContainsAny(value, "%#\\\r\n\t ") {
		return "", errors.New("invalid URI characters")
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "spiffe") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Port() != "" || u.Host == "" {
		return "", errors.New("URI requires https/spiffe and a plain host without credentials, port, query or fragment")
	}
	host, err := dnsName(u.Host, false)
	if err != nil {
		return "", err
	}
	u.Host = host
	if !strings.HasPrefix(u.Path, "/") {
		return "", errors.New("URI requires an absolute path")
	}
	for _, c := range u.Path {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:@/", c)) {
			return "", errors.New("URI path requires unescaped RFC 3986 path characters")
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return "", errors.New("URI dot paths are not allowed")
		}
	}
	if u.EscapedPath() != u.Path {
		return "", errors.New("URI path contains characters requiring escaping")
	}
	return u.String(), nil
}

func (p *Policy) Validate() error {
	if p.Version != 1 || p.DefaultValiditySeconds < 60 || p.DefaultValiditySeconds > p.MaxValiditySeconds || p.MaxValiditySeconds > maxValidity || p.MaxSANs < 1 || p.MaxSANs > 100 {
		return invalid("Policy v1 requires 60..34300800 second validity, default <= maximum, and 1..100 SANs")
	}
	if len(p.ExtendedKeyUsages) == 0 || len(p.ExtendedKeyUsages) > 2 {
		return invalid("Choose server_auth and/or client_auth")
	}
	seen := map[string]bool{}
	for _, usage := range p.ExtendedKeyUsages {
		if (usage != "server_auth" && usage != "client_auth") || seen[usage] {
			return invalid("Invalid or repeated extended key usage")
		}
		seen[usage] = true
	}
	if len(p.AllowedDNSNames)+len(p.AllowedIPRanges)+len(p.AllowedEmailDomains)+len(p.AllowedURIPrefixes) == 0 {
		return invalid("At least one explicit identity allow-list is required")
	}
	for _, size := range []int{len(p.AllowedDNSNames), len(p.AllowedIPRanges), len(p.AllowedEmailDomains), len(p.AllowedURIPrefixes)} {
		if size > 100 {
			return invalid("Each identity allow-list is limited to 100 entries")
		}
	}
	for i, name := range p.AllowedDNSNames {
		n, err := dnsName(name, true)
		if err != nil {
			return invalid(err.Error())
		}
		p.AllowedDNSNames[i] = n
	}
	for i, value := range p.AllowedIPRanges {
		network, err := netip.ParsePrefix(value)
		if err != nil || network.Addr().Is4In6() {
			return invalid("Invalid CIDR; use native IPv4 or IPv6 prefixes")
		}
		p.AllowedIPRanges[i] = network.Masked().String()
	}
	for i, name := range p.AllowedEmailDomains {
		n, err := dnsName(name, false)
		if err != nil {
			return invalid("Invalid email domain")
		}
		p.AllowedEmailDomains[i] = n
	}
	for i, value := range p.AllowedURIPrefixes {
		n, err := uriName(value)
		if err != nil {
			return invalid(err.Error())
		}
		p.AllowedURIPrefixes[i] = n
	}
	// Keep API arrays consistent even when optional lists were omitted.
	if p.AllowedDNSNames == nil {
		p.AllowedDNSNames = []string{}
	}
	if p.AllowedIPRanges == nil {
		p.AllowedIPRanges = []string{}
	}
	if p.AllowedEmailDomains == nil {
		p.AllowedEmailDomains = []string{}
	}
	if p.AllowedURIPrefixes == nil {
		p.AllowedURIPrefixes = []string{}
	}
	return nil
}

func allowedDNS(name string, p Policy) bool {
	if strings.HasPrefix(name, "*.") && !p.AllowWildcards {
		return false
	}
	for _, rule := range p.AllowedDNSNames {
		if rule == name {
			return true
		}
		if strings.HasPrefix(rule, "*.") {
			base := rule[2:]
			if strings.HasSuffix(name, "."+base) {
				left := strings.TrimSuffix(name, "."+base)
				if left != "" && !strings.Contains(left, ".") && left != "*" {
					return true
				}
			}
		}
	}
	return false
}

func checkKey(public any) error {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key.E < 65537 || (key.N.BitLen() != 2048 && key.N.BitLen() != 3072 && key.N.BitLen() != 4096) {
			return invalid("RSA requires 2048/3072/4096 bits and exponent >=65537")
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() {
			return invalid("ECDSA requires P-256/P-384")
		}
	default:
		return invalid("Unsupported public key algorithm")
	}
	return nil
}

func parseCSR(value string) (*x509.CertificateRequest, error) {
	if len(value) > 64<<10 {
		return nil, invalid("CSR exceeds 64 KiB")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" || !strings.HasPrefix(strings.TrimSpace(value), "-----BEGIN CERTIFICATE REQUEST-----") {
		return nil, invalid("Provide exactly one PKCS#10 PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, invalid("Invalid CSR")
	}
	switch csr.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
	default:
		return nil, invalid("CSR requires SHA-256/384/512 signatures")
	}
	if err := checkKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if csr.CheckSignature() != nil {
		return nil, invalid("Invalid CSR signature")
	}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return nil, invalid("Only the SAN request extension is accepted; certificate constraints are set by the server")
		}
	}
	// Go exposes only supported GeneralName types; reject hidden otherName/registeredID etc.
	for _, ext := range csr.Extensions {
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil || len(rest) != 0 || seq.Tag != asn1.TagSequence || seq.Class != 0 {
			return nil, invalid("Invalid SAN extension")
		}
		for data := seq.Bytes; len(data) > 0; {
			var entry asn1.RawValue
			data, err = asn1.Unmarshal(data, &entry)
			if err != nil || entry.Class != 2 || entry.IsCompound || (entry.Tag != 1 && entry.Tag != 2 && entry.Tag != 6 && entry.Tag != 7) {
				return nil, invalid("Unsupported SAN type")
			}
		}
	}
	counts := map[string]int{}
	for _, name := range csr.Subject.Names {
		id := name.Type.String()
		if !slices.Contains([]string{"2.5.4.3", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.10", "2.5.4.11"}, id) {
			return nil, invalid("Unsupported subject attribute")
		}
		v, ok := name.Value.(string)
		if !ok || len(v) > 128 || strings.ContainsFunc(v, unicode.IsControl) {
			return nil, invalid("Invalid subject attribute")
		}
		counts[id]++
		if counts[id] > 8 || (id == "2.5.4.3" && counts[id] > 1) {
			return nil, invalid("Too many repeated subject attributes")
		}
		if id == "2.5.4.6" && (len(v) != 2 || v[0] < 'A' || v[0] > 'Z' || v[1] < 'A' || v[1] > 'Z') {
			return nil, invalid("Country requires two uppercase ASCII letters")
		}
	}
	for i, name := range csr.DNSNames {
		n, err := dnsName(name, true)
		if err != nil {
			return nil, invalid(err.Error())
		}
		csr.DNSNames[i] = n
	}
	for i, value := range csr.EmailAddresses {
		address, err := mail.ParseAddress(value)
		at := strings.LastIndex(value, "@")
		if err != nil || address.Address != value || at < 1 || at > 64 || len(value) > 254 {
			return nil, invalid("Invalid email SAN")
		}
		for _, c := range value[:at] {
			if c < 33 || c > 126 {
				return nil, invalid("Email local part must be ASCII")
			}
		}
		domain, err := dnsName(value[at+1:], false)
		if err != nil {
			return nil, invalid("Invalid email domain")
		}
		csr.EmailAddresses[i] = value[:at] + "@" + domain
	}
	for i, value := range csr.URIs {
		n, err := uriName(value.String())
		if err != nil {
			return nil, invalid(err.Error())
		}
		csr.URIs[i], _ = url.Parse(n)
	}
	return csr, nil
}

func validateRequest(csr *x509.CertificateRequest, p Policy) error {
	count := len(csr.DNSNames) + len(csr.IPAddresses) + len(csr.EmailAddresses) + len(csr.URIs)
	if count < 1 || count > p.MaxSANs {
		return invalid("CSR SAN count is outside policy limits")
	}
	identities := []string{}
	for _, name := range csr.DNSNames {
		if !allowedDNS(name, p) {
			return invalid("DNS SAN is outside the allow-list")
		}
		identities = append(identities, name)
	}
	for _, ip := range csr.IPAddresses {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return invalid("Invalid IP SAN")
		}
		addr = addr.Unmap()
		allowed := false
		for _, value := range p.AllowedIPRanges {
			prefix, _ := netip.ParsePrefix(value)
			if prefix.Contains(addr) {
				allowed = true
			}
		}
		if !allowed {
			return invalid("IP SAN is outside the allow-list")
		}
		identities = append(identities, addr.String())
	}
	for _, value := range csr.EmailAddresses {
		if !slices.Contains(p.AllowedEmailDomains, value[strings.LastIndex(value, "@")+1:]) {
			return invalid("Email SAN is outside the allow-list")
		}
		identities = append(identities, value)
	}
	for _, value := range csr.URIs {
		name := value.String()
		allowed := false
		for _, prefix := range p.AllowedURIPrefixes {
			if name == prefix || strings.HasPrefix(name, strings.TrimSuffix(prefix, "/")+"/") {
				allowed = true
			}
		}
		if !allowed {
			return invalid("URI SAN is outside the allow-list")
		}
		identities = append(identities, name)
	}
	if cn := csr.Subject.CommonName; cn != "" {
		candidate := cn
		if n, err := dnsName(cn, true); err == nil {
			candidate = n
		}
		if addr, err := netip.ParseAddr(cn); err == nil {
			candidate = addr.Unmap().String()
		}
		if !slices.Contains(identities, candidate) {
			return invalid("Common Name must match an allowed SAN")
		}
		csr.Subject.CommonName = candidate
	}
	return nil
}
