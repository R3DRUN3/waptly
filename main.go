package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"waptly/checks"

	_ "waptly/checks"
)

var version = "dev"

// TargetReport holds all check results for a single target URL.
type TargetReport struct {
	Target string          `json:"target"`
	Error  string          `json:"error,omitempty"`
	Checks []checks.Result `json:"checks,omitempty"`
}

// Report is the top-level JSON output.
type Report struct {
	Version     string         `json:"version"`
	GeneratedAt string         `json:"generated_at"`
	Targets     []TargetReport `json:"targets"`
}

const (
	defaultWorkers = 20 // concurrent goroutines
	httpTimeout    = 10 * time.Second
)

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: waptly [--verbose] <url1> [url2] ...")
		fmt.Fprintln(os.Stderr, "Example: waptly https://example.com https://another.com")
		os.Exit(1)
	}

	verbose := false
	var targetArgs []string
	for _, arg := range args {
		if arg == "--verbose" || arg == "-verbose" || arg == "-v" {
			verbose = true
		} else {
			targetArgs = append(targetArgs, arg)
		}
	}

	if len(targetArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: waptly [--verbose] <url1> [url2] ...")
		fmt.Fprintln(os.Stderr, "Example: waptly https://example.com https://another.com")
		os.Exit(1)
	}

	targets := parseTargets(targetArgs)

	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	results := runScans(client, targets, defaultWorkers)

	if !verbose {
		for i := range results {
			filtered := results[i].Checks[:0]
			for _, c := range results[i].Checks {
				if !c.Passed {
					filtered = append(filtered, c)
				}
			}
			results[i].Checks = filtered
		}
	}

	report := Report{
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Targets:     results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode report: %v\n", err)
		os.Exit(1)
	}
}

// runScans fans out target scanning across a pool of `workers` goroutines.
// Results are collected in the original target order.
func runScans(client *http.Client, targets []string, workers int) []TargetReport {
	type indexedResult struct {
		index  int
		report TargetReport
	}

	jobs := make(chan struct {
		index  int
		target string
	}, len(targets))

	resultsCh := make(chan indexedResult, len(targets))

	// Start the worker pool.
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				resultsCh <- indexedResult{
					index:  job.index,
					report: scanTarget(client, job.target),
				}
			}
		}()
	}

	// Feed all targets into the jobs channel, then close it.
	for i, target := range targets {
		jobs <- struct {
			index  int
			target string
		}{i, target}
	}
	close(jobs)

	// Wait for all workers to finish, then close the results channel.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results preserving original order.
	ordered := make([]TargetReport, len(targets))
	for r := range resultsCh {
		ordered[r.index] = r.report
	}

	return ordered
}

// scanTarget fetches the target URL and runs all registered checks against it.
func scanTarget(client *http.Client, target string) TargetReport {
	report := TargetReport{Target: target}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		report.Error = fmt.Sprintf("invalid URL: %v", err)
		return report
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		report.Error = fmt.Sprintf("request failed: %v", err)
		return report
	}
	defer resp.Body.Close()

	for _, check := range checks.All() {
		result := check.Run(target, resp)
		report.Checks = append(report.Checks, result)
	}

	return report
}

// parseTargets normalises CLI args: handles comma-separated and trailing commas.
func parseTargets(args []string) []string {
	var targets []string
	for _, arg := range args {
		for _, t := range strings.Split(arg, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
				t = "https://" + t
			}
			targets = append(targets, t)
		}
	}
	return targets
}
