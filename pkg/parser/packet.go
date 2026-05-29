package parser

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ParsedPacket contains extracted layer information from a raw packet.
type ParsedPacket struct {
	Timestamp   string
	SrcMAC      string
	DstMAC      string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Protocol    string
	Payload     []byte
	PayloadStr  string
	Length      int
}

// ParsePacket decodes a gopacket.Packet into our custom ParsedPacket structure.
func ParsePacket(packet gopacket.Packet) (*ParsedPacket, error) {
	if packet == nil {
		return nil, fmt.Errorf("packet is nil")
	}

	parsed := &ParsedPacket{
		Timestamp: packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000"),
		Length:    packet.Metadata().Length,
	}

	// 1. Ethernet Layer (MAC Addresses)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		eth, _ := ethernetLayer.(*layers.Ethernet)
		parsed.SrcMAC = eth.SrcMAC.String()
		parsed.DstMAC = eth.DstMAC.String()
	}

	// 2. Network Layer (IP Addresses)
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)
		parsed.SrcIP = ip.SrcIP.String()
		parsed.DstIP = ip.DstIP.String()
		parsed.Protocol = "IPv4"
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip, _ := ip6Layer.(*layers.IPv6)
		parsed.SrcIP = ip.SrcIP.String()
		parsed.DstIP = ip.DstIP.String()
		parsed.Protocol = "IPv6"
	}

	// 3. Transport Layer (Ports)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		parsed.SrcPort = uint16(tcp.SrcPort)
		parsed.DstPort = uint16(tcp.DstPort)
		parsed.Protocol += "/TCP"
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		parsed.SrcPort = uint16(udp.SrcPort)
		parsed.DstPort = uint16(udp.DstPort)
		parsed.Protocol += "/UDP"
	}

	// 4. Application Layer / Payload
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		parsed.Payload = appLayer.Payload()
		parsed.PayloadStr = getPrintablePayload(parsed.Payload, 64) // Snippet of max 64 chars
	}

	return parsed, nil
}

// getPrintablePayload attempts to convert raw bytes to a clean ASCII string snippet.
func getPrintablePayload(payload []byte, maxLen int) string {
	if len(payload) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, b := range payload {
		if i >= maxLen {
			sb.WriteString("...")
			break
		}
		// Basic printable ASCII check
		if b >= 32 && b <= 126 {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.') // replace non-printable with dot
		}
	}
	return sb.String()
}
