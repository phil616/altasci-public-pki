package signing

import (
	"strings"
	"testing"
)

// Persisted policy identifiers must not become invalid on the next request.
func FuzzIdentifierNormalization(f *testing.F) {
	for _, value := range []string{"example.test", "*.example.test", "BÜCHER.example", "spiffe://example.test/workloads/a", "https://example.test/a\"b", "https://example.test/{id}", "https://example.test/a#"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			return
		}
		if normalized, err := dnsName(value, true); err == nil {
			if len(normalized) > 253 {
				t.Fatal("DNS identifier exceeds maximum length")
			}
			second, err := dnsName(normalized, true)
			if err != nil || second != normalized {
				t.Fatalf("unstable DNS normalization: %q -> %q: %v", value, normalized, err)
			}
		}
		if normalized, err := uriName(value); err == nil {
			if strings.ContainsAny(normalized, "%#\\") {
				t.Fatal("URI escaped forbidden characters")
			}
			second, err := uriName(normalized)
			if err != nil || second != normalized {
				t.Fatalf("unstable URI normalization: %q -> %q: %v", value, normalized, err)
			}
		}
	})
}

func TestWildcardCountsTowardDNSLength(t *testing.T) {
	base := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(base) != 253 {
		t.Fatal("bad test length")
	}
	if _, err := dnsName(base, false); err != nil {
		t.Fatal(err)
	}
	if _, err := dnsName("*."+base, true); err == nil {
		t.Fatal("overlong wildcard accepted")
	}
}
