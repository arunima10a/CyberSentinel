package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

type ScanResult struct {
	Target   string `json:"target"`
	Output   string `json:"output"`
	Status   string `json:"status"`
	PcapFile string `json:"pcap_file"`
}

func RunNmapScanWithCapture(target string) (ScanResult, error) {
	timestamp := time.Now().Format("20060102_150405")
	pcapPath := fmt.Sprintf("/app/evidence/capture_%s.pcap", timestamp)

	captureCmd := exec.Command("tshark", "-i", "eth0", "-w", pcapPath)
	if err := captureCmd.Start(); err != nil {
		fmt.Printf("ERROR: tshark capture failed to start on %s: %v\n", pcapPath, err)
	} else {
		fmt.Printf("[+] Packet capture initiated: %s (PID: %d)\n", pcapPath, captureCmd.Process.Pid)
	}

	time.Sleep(500 * time.Millisecond)

	ScanCmd := exec.Command("nmap", "-sV", target)
	output, ScanErr := ScanCmd.CombinedOutput()

	if captureCmd.Process != nil {
		time.Sleep(1 * time.Second)
		_ = captureCmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		_ = captureCmd.Process.Kill()
	}

	if ScanErr != nil {
		return ScanResult{Target: target, Status: "Failed"}, ScanErr
	}

	return ScanResult{
		Target:   target,
		Output:   string(output),
		Status:   "Completed",
		PcapFile: pcapPath,
	}, nil
}
