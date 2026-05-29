package sniffer

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Config holds the configuration for the sniffer engine.
type Config struct {
	Device      string
	PcapFile    string
	SnapLen     int32
	Promiscuous bool
	Timeout     time.Duration
}

// StartCapture initiates the packet capture loop (live or offline) and sends raw packets to a channel.
// The capture loop continues until the stopChan receives a signal.
func StartCapture(cfg Config, packetChan chan<- gopacket.Packet, stopChan <-chan struct{}) error {
	var handle *pcap.Handle
	var err error

	if cfg.PcapFile != "" {
		// Offline Capture Mode
		log.Printf("Starting offline capture from file: %s\n", cfg.PcapFile)
		handle, err = pcap.OpenOffline(cfg.PcapFile)
		if err != nil {
			return fmt.Errorf("error opening pcap file %s: %w", cfg.PcapFile, err)
		}
	} else if cfg.Device != "" {
		// Live Capture Mode
		log.Printf("Starting live capture on interface: %s\n", cfg.Device)
		handle, err = pcap.OpenLive(cfg.Device, cfg.SnapLen, cfg.Promiscuous, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("error opening live capture on device %s: %w", cfg.Device, err)
		}
	} else {
		return fmt.Errorf("either Device or PcapFile must be specified")
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sourceChan := packetSource.Packets()

	log.Println("Capture engine started. Listening for packets...")

	for {
		select {
		case <-stopChan:
			log.Println("Stop signal received. Halting capture loop.")
			return nil
		case packet, ok := <-sourceChan:
			if !ok {
				log.Println("Packet source channel closed (End of PCAP file or error).")
				return nil
			}
			// Send packet to the processing pipeline (non-blocking if buffered well)
			packetChan <- packet
		}
	}
}
