package scanner

import "os/exec"

type ScanResult struct {
	Target string `json:"target"`
	Output string `json:"output"`
	Status string `json:"status"`
}

func RunNmapScan(target string) (ScanResult, error) {
	cmd := exec.Command("nmap", "-sV", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ScanResult{Target: target, Status: "Failed"}, err
	}

	return ScanResult{
		Target: target,
		Output: string(output),
		Status: "Completed",
	}, nil
}
