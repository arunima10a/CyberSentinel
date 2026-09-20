package scanner

import (
	"regexp"
	"strconv"
	"strings"
)

type DiscoveredService struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type ParsedAssessment struct {
	Target  string              `json:"target"`
	Services []DiscoveredService `json:"services"`
	Raw     string              `json:"raw"`
}

func ParseNmapOutput(target, rawOutput string) ParsedAssessment {
	assessment := ParsedAssessment{
		Target:   target,
		Raw:      rawOutput,
		Services: []DiscoveredService{},
	}

	re := regexp.MustCompile(`(?m)^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$`)
	matches := re.FindAllStringSubmatch(rawOutput, -1)

	for _, match := range matches {
		if len(match) >= 5 {
			port, _ := strconv.Atoi(match[1])
			assessment.Services = append(assessment.Services, DiscoveredService{
				Port:     port,
				Protocol: match[2],
				State:    match[3],
				Service:  match[4],
				Version:  strings.TrimSpace(match[5]),
			})
		}
	}

	return assessment

}
