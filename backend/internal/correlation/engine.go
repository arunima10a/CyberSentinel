package correlation

import "fmt"

type TrafficFeatures struct {
	TotalPackets       int            `json:"total_packets"`
	SynCount           int            `json:"syn_count"`
	UniqueDestPorts    []int          `json:"unique_dest_ports"`
	SourceIps          map[string]int `json:"source_ips"`
	DetectedUserAgents []string       `json:"detected_user_agents"`
	TargetIP           string         `json:"target_ip"`
	AnalyzedFile       string         `json:"analyzed_file"`
	Error              string         `json:"error,omitempty"`
}

type Incident struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence_tags"`
}

func Correlate(openPortCount int, traffic TrafficFeatures) []Incident {
	incidents := []Incident{}

	if len(traffic.UniqueDestPorts) >= 3 || traffic.SynCount > 10 {
		topAttacker := "Unknown"
		highestPackets := 0
		for ip, count := range traffic.SourceIps {
			if count > highestPackets {
				highestPackets = count
				topAttacker = ip
			}
		}

		incidents = append(incidents, Incident{
			Type:        "Active Network Reconnaissance (Port Scan)",
			Severity:    "HIGH",
			Confidence:  92,
			Description: fmt.Sprintf("Source %s scanned %d unique destination ports using %d TCP SYN packets.", topAttacker, len(traffic.UniqueDestPorts), traffic.SynCount),
			Evidence: []string{
				fmt.Sprintf("Probed Ports: %v", traffic.UniqueDestPorts),
				fmt.Sprintf("Attacker IP: %s", topAttacker),
				fmt.Sprintf("SYN Packets: %d", traffic.SynCount),
			},
		})
	}

	for _, ua := range traffic.DetectedUserAgents {
		if len(ua) > 0 && (contains(ua, "Nmap") || contains(ua, "nmap")) {
			incidents = append(incidents, Incident{
				Type:        "Automated Vulnerability Tooling Detected",
				Severity:    "CRITICAL",
				Confidence:  98,
				Description: "HTTP traffic contained explicit scanner signatures matching the Nmap Scripting Engine (NSE).",
				Evidence: []string{
					fmt.Sprintf("User-Agent: %s", ua),
					fmt.Sprintf("Target Open Ports Discovered: %d", openPortCount),
					fmt.Sprintf("Pcap Artifact: %s", traffic.AnalyzedFile),
				},
			})
		}
	}

	if openPortCount > 0 && traffic.TotalPackets > 0 {
		incidents = append(incidents, Incident{
			Type:        "Exposed Service Attack Surface",
			Severity:    "MEDIUM",
			Confidence:  85,
			Description: fmt.Sprintf("Target host responded to probes with %d active listening service(s).", openPortCount),
			Evidence: []string{
				fmt.Sprintf("Verified Open Services: %d", openPortCount),
				fmt.Sprintf("Total Capture Volume: %d packets", traffic.TotalPackets),
			},
		})
	}

	return incidents
}

func contains(source, substr string) bool {
	return len(source) >= len(substr) && (source == substr || len(substr) == 0 || (len(source) > 0 && stringContains(source, substr)))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
