// checks/cookie_security.go
package checks

import (
	"net/http"
	"strings"
)

func init() { Register(&CookieSecurityCheck{}) }

type CookieFinding struct {
	Name            string `json:"name"`
	MissingSecure   bool   `json:"missing_secure"`
	MissingHttpOnly bool   `json:"missing_http_only"`
	MissingSameSite bool   `json:"missing_same_site"`
	Severity        string `json:"severity"`
}

type CookieSecurityCheck struct{}

func (c *CookieSecurityCheck) Name() string { return "cookie_security" }

func (c *CookieSecurityCheck) Run(_ string, resp *http.Response) Result {
	findings := []CookieFinding{}

	for _, raw := range resp.Header["Set-Cookie"] {
		lower := strings.ToLower(raw)
		name := strings.SplitN(raw, "=", 2)[0]

		f := CookieFinding{
			Name:            strings.TrimSpace(name),
			MissingSecure:   !strings.Contains(lower, "secure"),
			MissingHttpOnly: !strings.Contains(lower, "httponly"),
			MissingSameSite: !strings.Contains(lower, "samesite"),
		}

		issues := 0
		if f.MissingSecure {
			issues++
		}
		if f.MissingHttpOnly {
			issues++
		}
		if f.MissingSameSite {
			issues++
		}

		switch {
		case issues >= 2:
			f.Severity = "high"
		case issues == 1:
			f.Severity = "medium"
		}

		if issues > 0 {
			findings = append(findings, f)
		}
	}

	return Result{
		CheckName: c.Name(),
		Passed:    len(findings) == 0,
		Details: map[string]any{
			"findings":              findings,
			"total_cookies_checked": len(resp.Header["Set-Cookie"]),
		},
	}
}
