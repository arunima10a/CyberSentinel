package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"time"
)

type AttackResult struct {
	Target       string   `json:"target"`
	AttackType   string   `json:"attack_type"`
	Attempts     int      `json:"attempts"`
	FailedLogins int      `json:"failed_logins"`
	Credentials  []string `json:"tried_credentials"`
	Duration     string   `json:"duration"`
	Status       string   `json:"status"`
}

// RunSSHBruteForce simulates rapid failed SSH authentication attempts against target-ssh
func RunSSHBruteForce(target string) AttackResult {
	start := time.Now()
	passwords := []string{"admin", "123456", "root", "toor", "guest", "qwerty"}
	failed := 0
	tried := []string{}

	for _, pwd := range passwords {
		tried = append(tried, fmt.Sprintf("labuser:%s", pwd))
		// Attempt a raw TCP handshake on port 22 with SSH identification exchange
		conn, err := net.DialTimeout("tcp", target+":22", 1*time.Second)
		if err == nil {
			// Read SSH banner
			buf := make([]byte, 128)
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = conn.Read(buf)

			// Send dummy SSH identification to simulate failed handshake
			_, _ = conn.Write([]byte("SSH-2.0-CyberSentinel_Attacker\r\n"))
			_ = conn.Close()
			failed++
		}
		time.Sleep(100 * time.Millisecond)
	}

	return AttackResult{
		Target:       target,
		AttackType:   "SSH Credential Brute Force",
		Attempts:     len(passwords),
		FailedLogins: failed,
		Credentials:  tried,
		Duration:     time.Since(start).String(),
		Status:       "Completed",
	}
}

// RunTargetScan runs nmap against any chosen target with packet capture
func RunTargetScan(target string) (ScanResult, error) {
	ports := map[string]string{
		"target-web": "80",
		"target-ssh": "22",
	}
	port, ok := ports[target]
	if !ok {
		return ScanResult{Target: target, Status: "Failed"}, fmt.Errorf("unsupported scan target %q", target)
	}

	timestamp := time.Now().Format("20060102_150405")
	pcapPath := fmt.Sprintf("/app/evidence/capture_%s_%s.pcap", target, timestamp)

	captureCmd := exec.Command("tshark", "-i", "eth0", "-w", pcapPath)
	_ = captureCmd.Start()
	time.Sleep(500 * time.Millisecond)

	// Scan the service port used by the selected lab target. -Pn avoids Nmap
	// skipping containers that don't answer host-discovery probes.
	scanCmd := exec.Command("nmap", "-sV", "-Pn", "-p", port, target)
	output, scanErr := scanCmd.CombinedOutput()

	if captureCmd.Process != nil {
		time.Sleep(1 * time.Second)
		_ = captureCmd.Process.Kill()
	}

	if scanErr != nil {
		return ScanResult{Target: target, Status: "Failed"}, scanErr
	}

	return ScanResult{
		Target:   target,
		Output:   string(output),
		Status:   "Completed",
		PcapFile: pcapPath,
	}, nil
}
