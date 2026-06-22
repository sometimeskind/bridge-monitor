package serve

import (
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"no origin (curl)", "", "bridge-reauth.prins.id", true},
		{"matching origin", "https://bridge-reauth.prins.id", "bridge-reauth.prins.id", true},
		{"cross-site origin", "https://evil.example", "bridge-reauth.prins.id", false},
		{"malformed origin", "://bad", "bridge-reauth.prins.id", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/auth", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := sameOrigin(r); got != c.want {
				t.Errorf("sameOrigin(origin=%q, host=%q) = %v, want %v", c.origin, c.host, got, c.want)
			}
		})
	}
}
