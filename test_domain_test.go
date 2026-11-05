package authwave

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestProviderTestDomainPolicy(t *testing.T) {
	cases := []struct {
		host    string
		allowed bool
	}{
		{"http://login.realtest.authwave.test:9090", true},
		{"http://app.test", true},
		{"http://LOGIN.EXAMPLE.TEST:9090", true},
		{"http://login.example.test.:9090", true},
		{"http://localhost:9090", true},
		{"http://127.0.0.127:9090", true},
		{"https://login.authwave.com", true},
		{"http://login.realtest.authwave-test:9090", false},
		{"http://example.test.attacker.com", false},
		{"http://exampletest", false},
		{"http://test", false},
		{"http://login.authwave.com", false},
		{"ftp://example.test", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			uri, err := NewAdminURI(tc.host)
			if !tc.allowed {
				if !errors.Is(err, ErrInsecureProtocol) {
					t.Fatalf("expected insecure protocol error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Path != "/admin/" {
				t.Fatal(uri)
			}
			if strings.HasPrefix(tc.host, "http://") && parsed.Scheme != "http" {
				t.Fatal(uri)
			}
			if strings.Contains(tc.host, ":9090") && parsed.Port() != "9090" {
				t.Fatal(uri)
			}
		})
	}
}
