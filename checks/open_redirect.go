package checks

import (
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

func init() { Register(&OpenRedirectCheck{}) }

type OpenRedirectFinding struct {
	Parameter  string `json:"parameter"`
	Payload    string `json:"payload"`
	TestURL    string `json:"test_url"`
	RedirectTo string `json:"redirect_to"`
}

type OpenRedirectCheck struct{}

func (c *OpenRedirectCheck) Name() string { return "open_redirect" }

type redirectTestCase struct {
	PathSuffix string
	Param      string
}

// The check makes HEAD requests to the target with common redirect params.
func (c *OpenRedirectCheck) Run(target string, _ *http.Response) Result {
	findings := []OpenRedirectFinding{}

	testCases := []redirectTestCase{
		{PathSuffix: "", Param: "redirect"},
		{PathSuffix: "", Param: "url"},
		{PathSuffix: "", Param: "next"},
		{PathSuffix: "", Param: "dest"},
		{PathSuffix: "", Param: "destination"},
		{PathSuffix: "", Param: "return"},
		{PathSuffix: "", Param: "redir"},
		{PathSuffix: "", Param: "continue"},
		{PathSuffix: "/redirect", Param: "to"},
	}

	payloads := []string{
		"https://github.com",
		"http://github.com",
		"//github.com",
		"///github.com",
		"/\\github.com",
		"\\\\github.com",
		"https:github.com",
		"%2F%2Fgithub.com",
		"%252F%252Fgithub.com",
		"https://github.com%20",
		"%20https://github.com",
		"https://github.com%09",
		"https://github.com%0a",
		"https://github.com%0d",
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, tc := range testCases {
		for _, payload := range payloads {
			testURL, err := buildRedirectTestURL(target, tc.PathSuffix, tc.Param, payload)
			if err != nil {
				continue
			}

			resp, err := client.Head(testURL)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" &&
				(loc == payload || strings.HasPrefix(loc, payload)) {
				findings = append(findings, OpenRedirectFinding{
					Parameter:  tc.Param,
					Payload:    payload,
					TestURL:    testURL,
					RedirectTo: loc,
				})
			}
		}
	}

	return Result{
		CheckName: c.Name(),
		Passed:    len(findings) == 0,
		Details: map[string]any{
			"findings": findings,
		},
	}
}

func buildRedirectTestURL(baseURL, pathSuffix, key, val string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	if pathSuffix != "" {
		parsed.Path = path.Join(parsed.Path, pathSuffix)
	}

	q := parsed.Query()
	q.Set(key, val)
	parsed.RawQuery = q.Encode()

	return parsed.String(), nil
}
