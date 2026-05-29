package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	
	"network-analyzer/pkg/analyzer"
	"network-analyzer/pkg/config"
	"network-analyzer/pkg/parser"
	"network-analyzer/pkg/sniffer"
)

func main() {
	var interfaceName string
	var pcapFile string
	var configFile string

	flag.StringVar(&interfaceName, "i", "", "Network interface to sniff (live capture)")
	flag.StringVar(&pcapFile, "f", "", "PCAP file to read (offline analysis)")
	flag.StringVar(&configFile, "c", "rules.json", "Path to rules configuration JSON file")
	flag.Parse()

	fmt.Println("==================================================")
	fmt.Println("          Network Packet Analyzer v1.0")
	fmt.Println("==================================================")

	// Load Configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Printf("Warning: Failed to load config from %s: %v. Using defaults.\n", configFile, err)
		cfg = &config.Config{
			PortScanThreshold: 20,
			PortScanWindowSec: 10,
		}
	} else {
		log.Printf("Loaded configuration with %d rules.\n", len(cfg.Rules))
	}

	// Initialize Analyzer Engine
	analyzeEngine, err := analyzer.NewEngine(cfg, "alerts.json")
	if err != nil {
		log.Fatalf("Fatal: Failed to initialize analyzer engine: %v", err)
	}
	defer analyzeEngine.Close()

	// Channels for pipeline
	packetChan := make(chan gopacket.Packet, 1000) // Buffer to handle bursts
	stopChan := make(chan struct{})

	var wg sync.WaitGroup

	// 1. Start Analysis Worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("Analysis worker started.")
		for {
			select {
			case <-stopChan:
				// Process remaining packets before exit? (Optional based on design)
				log.Println("Analysis worker shutting down.")
				return
			case packet, ok := <-packetChan:
				if !ok {
					return
				}
				
				parsed, err := parser.ParsePacket(packet)
				if err != nil {
					// Silent continue on unparseable packets for now
					continue
				}

				// Print live basic packet info (optional, could be toggled with verbose flag)
				if parsed.Protocol != "" {
					fmt.Printf("[%s] %s | %s:%d -> %s:%d | Len: %d\n", 
						parsed.Timestamp, parsed.Protocol, 
						parsed.SrcIP, parsed.SrcPort, 
						parsed.DstIP, parsed.DstPort, 
						parsed.Length)
				}

				// Analyze
				analyzeEngine.ProcessPacket(parsed)
			}
		}
	}()

	// OS Signal Handling for Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\n[!] Interrupt signal received. Initiating graceful shutdown...")
		close(stopChan)
	}()

	// 2. Start Sniffer Engine (Blocking call until stopped or file ends)
	sniffCfg := sniffer.Config{
		Device:      interfaceName,
		PcapFile:    pcapFile,
		SnapLen:     65536,
		Promiscuous: true,
		Timeout:     pcap.BlockForever, // Or a specific timeout
	}

	err = sniffer.StartCapture(sniffCfg, packetChan, stopChan)
	if err != nil {
		log.Fatalf("Capture engine error: %v", err)
	}

	// Wait for analysis worker to finish cleanup
	wg.Wait()
	fmt.Println("Shutdown complete. Alerts (if any) saved to alerts.json.")
}
