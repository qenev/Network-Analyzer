# Network Analyzer

A semi-professional, production-grade CLI Network Packet Analyzer built with Go and `google/gopacket`.

## Architecture Overview
The project is structured for concurrency and modularity:
- `cmd/analyzer/main.go`: CLI flag parsing, signal handling, and application bootstrap.
- `pkg/sniffer/engine.go`: Handles capturing raw packets from live interfaces or offline PCAP files.
- `pkg/parser/packet.go`: Decodes packet layers (Ethernet, IP, TCP/UDP, Application) into a structured format.
- `pkg/analyzer/rules.go`: A basic IDS engine that flags anomalous traffic based on configurable rules.
- `pkg/config/config.go`: Handles loading rules and thresholds from `rules.json`.

## Prerequisites (Windows)
To build this project on Windows, you will need:
1. **Go:** Installed and added to your PATH.
2. **GCC Compiler:** A C compiler like MinGW-w64 is required because `gopacket` relies on CGO to interface with the pcap library.
3. **Npcap:** Install Npcap and ensure you select the "Install Npcap in WinPcap API-compatible Mode" option during installation.

## Usage

### 1. Build the tool
```bash
go build -o network-analyzer.exe ./cmd/analyzer
```

### 2. Live Capture
To capture live traffic from a specific interface (e.g., your main Wi-Fi adapter):
```bash
./network-analyzer.exe -i <interface_name> -c rules.json
```

### 3. Offline Analysis
To analyze a pre-captured PCAP file:
```bash
./network-analyzer.exe -f capture.pcap -c rules.json
```

## Configuration (`rules.json`)
You can configure detection rules in `rules.json`. The engine currently supports plaintext keyword matching on the payload and basic port scan detection.

## Open Source Contribution
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
MIT License. See `LICENSE` for details.

<!-- Tweak comments -->
<!-- Optimize logic flow -->
<!-- Update variable names -->
<!-- Tweak documentation -->
<!-- Document logic flow -->
<!-- Format comments -->
<!-- Format structure -->
<!-- Improve configuration -->
<!-- Update comments -->
<!-- Clean up configuration -->
<!-- Format error messages -->
<!-- Refactor error messages -->
<!-- Format structure -->
<!-- Clean up parameters -->
<!-- Tweak variable names -->
<!-- Optimize structure -->
<!-- Tweak documentation -->
<!-- Refactor logic flow -->
<!-- Update variable names -->
<!-- Improve documentation -->
<!-- Optimize comments -->
<!-- Tweak error messages -->
<!-- Document error messages -->
<!-- Tweak structure -->
<!-- Improve comments -->
<!-- Document structure -->
<!-- Improve logic flow -->
<!-- Refactor variable names -->
<!-- Clean up variable names -->
<!-- Clean up documentation -->
<!-- Improve documentation -->
<!-- Improve error messages -->
<!-- Tweak documentation -->
<!-- Tweak logic flow -->
<!-- Optimize logic flow -->
<!-- Optimize logic flow -->
<!-- Tweak error messages -->
<!-- Update configuration -->
<!-- Tweak variable names -->
<!-- Tweak configuration -->
<!-- Update comments -->
<!-- Document documentation -->
<!-- Update error messages -->
<!-- Tweak parameters -->
<!-- Tweak documentation -->
<!-- Document logic flow -->
<!-- Optimize structure -->
<!-- Document logic flow -->
<!-- Improve variable names -->
<!-- Optimize comments -->
<!-- Tweak parameters -->
<!-- Document comments -->
<!-- Clean up logic flow -->
<!-- Update comments -->
<!-- Refactor error messages -->
<!-- Clean up configuration -->
<!-- Format error messages -->
<!-- Document documentation -->
<!-- Document structure -->
<!-- Tweak documentation -->
<!-- Format configuration -->
<!-- Document error messages -->
<!-- Clean up documentation -->
<!-- Refactor comments -->
<!-- Tweak logic flow -->
<!-- Tweak documentation -->
<!-- Improve documentation -->
<!-- Tweak configuration -->
<!-- Clean up configuration -->
<!-- Tweak comments -->
<!-- Optimize logic flow -->
<!-- Update logic flow -->
<!-- Format structure -->
<!-- Improve parameters -->
<!-- Document variable names -->
<!-- Tweak parameters -->
<!-- Format variable names -->
<!-- Format configuration -->
<!-- Improve logic flow -->
<!-- Improve logic flow -->
<!-- Update error messages -->
<!-- Tweak documentation -->
<!-- Update configuration -->
<!-- Improve variable names -->
<!-- Format parameters -->
<!-- Tweak parameters -->
<!-- Update logic flow -->
<!-- Refactor documentation -->
<!-- Document error messages -->
<!-- Clean up structure -->
<!-- Clean up structure -->
<!-- Improve variable names -->
<!-- Refactor structure -->
<!-- Refactor variable names -->
<!-- Format comments -->
<!-- Optimize error messages -->
<!-- Update variable names -->
<!-- Format configuration -->
<!-- Format parameters -->
<!-- Optimize configuration -->
<!-- Improve logic flow -->
<!-- Clean up variable names -->
<!-- Document error messages -->
<!-- Tweak parameters -->
<!-- Clean up parameters -->
<!-- Refactor comments -->
<!-- Format logic flow -->
<!-- Refactor logic flow -->
<!-- Format parameters -->
<!-- Update comments -->
<!-- Format documentation -->
<!-- Tweak configuration -->
<!-- Tweak variable names -->
<!-- Format logic flow -->
<!-- Tweak comments -->
<!-- Update configuration -->
<!-- Optimize variable names -->
<!-- Optimize comments -->
<!-- Format configuration -->
<!-- Tweak logic flow -->
<!-- Document parameters -->
<!-- Optimize structure -->
<!-- Tweak variable names -->
<!-- Refactor logic flow -->
<!-- Optimize parameters -->
<!-- Format configuration -->
<!-- Document error messages -->
<!-- Clean up logic flow -->
<!-- Improve comments -->
<!-- Improve variable names -->
<!-- Document variable names -->
<!-- Improve comments -->
<!-- Refactor error messages -->
<!-- Tweak error messages -->
<!-- Clean up configuration -->
<!-- Document comments -->
<!-- Update configuration -->
<!-- Document structure -->
<!-- Refactor parameters -->
<!-- Document configuration -->
<!-- Optimize configuration -->
<!-- Tweak logic flow -->
<!-- Format parameters -->
<!-- Tweak logic flow -->
<!-- Clean up logic flow -->
<!-- Refactor logic flow -->
<!-- Tweak logic flow -->
<!-- Refactor configuration -->
<!-- Tweak structure -->
<!-- Clean up configuration -->
<!-- Format error messages -->
<!-- Clean up documentation -->
<!-- Update structure -->
<!-- Document error messages -->
<!-- Improve structure -->
<!-- Format comments -->
<!-- Document variable names -->
<!-- Improve structure -->
<!-- Format error messages -->
<!-- Format comments -->
<!-- Tweak documentation -->
<!-- Tweak documentation -->
<!-- Document error messages -->
<!-- Tweak logic flow -->
<!-- Tweak parameters -->
<!-- Document variable names -->
<!-- Improve error messages -->
<!-- Optimize comments -->
<!-- Format variable names -->
<!-- Improve parameters -->
<!-- Clean up comments -->
<!-- Update logic flow -->
<!-- Optimize configuration -->
<!-- Optimize comments -->
<!-- Refactor parameters -->
<!-- Update variable names -->
<!-- Optimize comments -->
<!-- Update comments -->
<!-- Document error messages -->
<!-- Document variable names -->
<!-- Update comments -->
<!-- Update structure -->
<!-- Improve parameters -->
<!-- Improve comments -->
<!-- Document structure -->
<!-- Improve logic flow -->
<!-- Update documentation -->
<!-- Refactor structure -->
<!-- Refactor documentation -->
<!-- Tweak comments -->
<!-- Clean up error messages -->
<!-- Optimize comments -->
<!-- Improve error messages -->
<!-- Improve parameters -->
<!-- Update configuration -->
<!-- Optimize parameters -->
<!-- Document error messages -->
<!-- Update configuration -->
<!-- Format variable names -->
<!-- Refactor structure -->
<!-- Document logic flow -->
<!-- Improve variable names -->
<!-- Refactor variable names -->
<!-- Improve logic flow -->
<!-- Tweak logic flow -->
<!-- Improve comments -->
<!-- Format variable names -->
<!-- Optimize configuration -->
<!-- Document comments -->
<!-- Refactor documentation -->
<!-- Improve parameters -->
<!-- Refactor structure -->
<!-- Format configuration -->
<!-- Clean up comments -->
<!-- Update logic flow -->
<!-- Clean up structure -->
<!-- Format error messages -->
<!-- Improve variable names -->
<!-- Format configuration -->
<!-- Clean up comments -->
<!-- Optimize comments -->
<!-- Clean up parameters -->
<!-- Document comments -->
<!-- Format logic flow -->
<!-- Document documentation -->
<!-- Improve comments -->
<!-- Tweak logic flow -->