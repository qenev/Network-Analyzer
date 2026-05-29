package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Rule represents a single detection rule.
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Action      string   `json:"action"` // e.g., "alert"
	Match       RuleMatch `json:"match"`
}

// RuleMatch contains the criteria for matching a rule.
type RuleMatch struct {
	Keywords  []string `json:"keywords,omitempty"`   // Plaintext keywords to look for in payload
	Protocols []string `json:"protocols,omitempty"`  // e.g., "tcp", "udp"
	SrcPorts  []uint16 `json:"src_ports,omitempty"`
	DstPorts  []uint16 `json:"dst_ports,omitempty"`
	// Additional match criteria can be added here (e.g., IPs, Regex)
}

// Config holds the application configuration.
type Config struct {
	Rules []Rule `json:"rules"`
	// Other global settings can go here (e.g., port scan threshold)
	PortScanThreshold int `json:"port_scan_threshold"` // Max unique ports per window
	PortScanWindowSec int `json:"port_scan_window_sec"` // Time window in seconds
}

// LoadConfig reads the configuration from a JSON file.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults if not provided
	if cfg.PortScanThreshold == 0 {
		cfg.PortScanThreshold = 20
	}
	if cfg.PortScanWindowSec == 0 {
		cfg.PortScanWindowSec = 10
	}

	return &cfg, nil
}
