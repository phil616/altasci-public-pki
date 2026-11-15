package httpapi

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/console/signing"
)

func TestSigningJSONRejectsAmbiguousRequests(t *testing.T) {
	for _, body := range []string{
		`null`, `[]`, `1`, `{"reason":null}`, `{"reason":0,"reason":1}`,
		`{"Reason":1}`, `{"reason":0,"Reason":1}`, `{"reason":{}}`, `{"reason":0} {}`,
		`{"reason":0.5}`, `{"reason":9223372036854775808}`,
	} {
		t.Run(body, func(t *testing.T) {
			w := httptest.NewRecorder()
			var input signing.RevokeInput
			if _, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", strings.NewReader(body)), &input); ok || w.Code != 400 {
				t.Fatalf("ambiguous request accepted: %s, %d", body, w.Code)
			}
		})
	}
	var input signing.RevokeInput
	w := httptest.NewRecorder()
	if _, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)), &input); !ok || input.Reason != 0 {
		t.Fatal("default revocation reason rejected")
	}
}

func TestSigningJSONChecksNestedFieldsAndNullablePolicy(t *testing.T) {
	for _, body := range []string{
		`{"name":"client","scopes":["issue"],"policy":{"version":1,"version":2}}`,
		`{"name":"client","scopes":["issue"],"policy":{"Version":1}}`,
		`{"name":"client","scopes":null}`,
		`{"name":"client","scopes":[null]}`,
	} {
		var input signing.CredentialInput
		w := httptest.NewRecorder()
		if _, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", strings.NewReader(body)), &input); ok {
			t.Fatal("invalid nested input accepted", body)
		}
	}
	var input signing.CredentialInput
	w := httptest.NewRecorder()
	body := `{"name":"client","scopes":["issue"],"policy":null}`
	if raw, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", strings.NewReader(body)), &input); !ok || string(raw) != body || input.Policy != nil {
		t.Fatal("nullable policy or raw retry bytes lost")
	}
	var issue signing.IssueInput
	w = httptest.NewRecorder()
	if _, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", bytes.NewReader(bytes.Repeat([]byte{' '}, (1<<20)+1))), &issue); ok || w.Code != 413 {
		t.Fatal("oversized signing input accepted", w.Code)
	}
}

func TestSigningJSONPreservesEmptyAllowListCompatibility(t *testing.T) {
	var input signing.CreateInput
	w := httptest.NewRecorder()
	body := `{"name":"instance","certificate_pem":"CA","private_key_pem":"KEY","policy":{"version":1,"allowed_dns_names":["example.test"],"allowed_ip_ranges":null,"allowed_email_domains":null,"allowed_uri_prefixes":null,"extended_key_usages":["server_auth"],"default_validity_seconds":3600,"max_validity_seconds":7200,"max_sans":2}}`
	if _, ok := decodeSigningJSON(w, httptest.NewRequest("POST", "/", strings.NewReader(body)), &input); !ok {
		t.Fatal("Go nil allow-list compatibility lost", w.Body.String())
	}
	if err := input.Policy.Validate(); err != nil {
		t.Fatal(err)
	}
	if input.Policy.AllowedIPRanges == nil {
		t.Fatal("empty allow-list was not normalized")
	}
}
