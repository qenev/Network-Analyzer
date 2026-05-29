package analyzer

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"network-analyzer/pkg/config"
	"network-analyzer/pkg/parser"
)

// Alert represents a triggered security alert.
type Alert struct {
	Timestamp   string              `json:"timestamp"`
	RuleID      string              `json:"rule_id"`
	Description string              `json:"description"`
	Severity    string              `json:"severity"`
	PacketInfo  *parser.ParsedPacket `json:"packet_info"`
}

// Engine processes packets against loaded rules.
type Engine struct {
	cfg         *config.Config
	alertsLog   *os.File
	alertsMutex sync.Mutex

	// Port scan tracking: Map of SrcIP -> map[DstPort]time.Time
	portScans      map[string]map[uint16]time.Time
	portScansMutex sync.RWMutex
}

// NewEngine initializes a new analysis engine.
func NewEngine(cfg *config.Config, logFilePath string) (*Engine, error) {
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open alerts log file: %w", err)
	}

	return &Engine{
		cfg:       cfg,
		alertsLog: file,
		portScans: make(map[string]map[uint16]time.Time),
	}, nil
}

// Close gracefully shuts down the engine and flushes files.
func (e *Engine) Close() error {
	return e.alertsLog.Close()
}

// ProcessPacket receives a parsed packet and runs it through the rule engine.
func (e *Engine) ProcessPacket(p *parser.ParsedPacket) {
	if p == nil {
		return
	}

	// 1. Check against static rules (e.g., cleartext passwords)
	e.checkStaticRules(p)

	// 2. Check for port scanning activity (anomalous behavior)
	e.checkPortScan(p)
}

func (e *Engine) checkStaticRules(p *parser.ParsedPacket) {
	for _, rule := range e.cfg.Rules {
		matched := false

		// Simple Keyword Matching (Case-Insensitive) on Payload
		if len(rule.Match.Keywords) > 0 && len(p.Payload) > 0 {
			payloadLower := strings.ToLower(string(p.Payload))
			for _, keyword := range rule.Match.Keywords {
				if strings.Contains(payloadLower, strings.ToLower(keyword)) {
					matched = true
					break
				}
			}
		}

		if matched {
			e.triggerAlert(rule.ID, rule.Description, "HIGH", p)
		}
	}
}

func (e *Engine) checkPortScan(p *parser.ParsedPacket) {
	if p.SrcIP == "" || p.DstPort == 0 {
		return
	}

	e.portScansMutex.Lock()
	defer e.portScansMutex.Unlock()

	now := time.Now()
	if _, exists := e.portScans[p.SrcIP]; !exists {
		e.portScans[p.SrcIP] = make(map[uint16]time.Time)
	}

	// Add the current port access
	e.portScans[p.SrcIP][p.DstPort] = now

	// Cleanup old entries outside the time window and count unique ports
	uniquePortsCount := 0
	windowStart := now.Add(-time.Duration(e.cfg.PortScanWindowSec) * time.Second)

	for port, timestamp := range e.portScans[p.SrcIP] {
		if timestamp.Before(windowStart) {
			delete(e.portScans[p.SrcIP], port)
		} else {
			uniquePortsCount++
		}
	}

	// Trigger alert if threshold exceeded
	if uniquePortsCount >= e.cfg.PortScanThreshold {
		// Prevent spamming the alert for the same IP continuously
		// A more robust implementation would cool down this alert.
		e.triggerAlert("ANOMALY-001", fmt.Sprintf("Potential Port Scan Detected from %s (%d unique ports)", p.SrcIP, uniquePortsCount), "WARNING", p)
		
		// Reset tracking for this IP after triggering to avoid log spam
		delete(e.portScans, p.SrcIP)
	}
}

func (e *Engine) triggerAlert(ruleID, description, severity string, p *parser.ParsedPacket) {
	alert := Alert{
		Timestamp:   time.Now().Format(time.RFC3339),
		RuleID:      ruleID,
		Description: description,
		Severity:    severity,
		PacketInfo:  p,
	}

	// 1. Output to Console (Colorized: Red bold for alert)
	fmt.Printf("\033[1;31m[!] ALERT [%s]: %s | Src: %s:%d -> Dst: %s:%d\033[0m\n", 
		alert.Severity, alert.Description, p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)

	// 2. Append to JSON log file
	e.alertsMutex.Lock()
	defer e.alertsMutex.Unlock()

	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("Failed to serialize alert: %v\n", err)
		return
	}
	
	e.alertsLog.Write(data)
	e.alertsLog.WriteString("\n")
}
