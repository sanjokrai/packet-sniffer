# Network Packet Sniffer with Message Decoder

A powerful Python-based packet sniffer that captures network traffic and automatically decodes encoded messages found in packet payloads.

## Features

- **Real-time Packet Capture**: Captures network packets using raw sockets
- **Protocol Support**: Parses Ethernet, IPv4, TCP, UDP, and ICMP protocols
- **Message Decoding**: Automatically detects and decodes:
  - Base64 encoding
  - Hexadecimal encoding
  - URL encoding
  - ROT13 cipher
  - Plain text messages
- **Detailed Analysis**: Displays comprehensive packet information including headers and payloads
- **Modular Design**: Clean separation of concerns across multiple modules

## File Structure

```
packet-sniffer/
│
├── main.py                 # Main application entry point
├── packet_capture.py       # Raw socket creation and packet capture
├── packet_parser.py        # Protocol parsing (Ethernet, IP, TCP, UDP, ICMP)
├── message_decoder.py      # Message decoding algorithms
├── packet_sniffer.py       # Main sniffer coordination class
└── README.md              # This file
```

## Requirements

- Python 3.6+
- Root/Administrator privileges (required for raw socket access)
- Operating Systems:
  - Linux (fully supported)
  - macOS (supported)
  - Windows (partial support, requires admin)

## Installation

No additional packages required! Uses only Python standard library.

```bash
# Clone or download the files to a directory
cd packet-sniffer

# Make executable (optional)
chmod +x main.py
```

## Usage

### Basic Usage

```bash
# Linux/Mac - requires sudo
sudo python3 main.py

# Windows - run Command Prompt as Administrator
python main.py
```

### Advanced Options

```bash
# Capture specific number of packets
sudo python3 main.py --count 50

# Specify network interface
sudo python3 main.py --interface eth0

# Quiet mode (only show packets with decoded messages)
sudo python3 main.py --quiet

# Combine options
sudo python3 main.py --count 100 --interface wlan0
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--count` | `-c` | Number of packets to capture | 20 |
| `--interface` | `-i` | Network interface to sniff on | auto-detect |
| `--quiet` | `-q` | Only show packets with decoded messages | False |

## How It Works

### 1. Packet Capture (`packet_capture.py`)
- Creates a raw socket with appropriate permissions
- Captures raw network packets from the network interface
- Handles different operating system implementations

### 2. Packet Parsing (`packet_parser.py`)
- Parses Ethernet frames (MAC addresses, protocol type)
- Parses IPv4 packets (source/dest IP, TTL, protocol)
- Parses TCP segments (ports, sequence numbers, flags)
- Parses UDP segments (ports, length)
- Parses ICMP packets (type, code)

### 3. Message Decoding (`message_decoder.py`)
- Scans packet payloads for encoded content
- Attempts multiple decoding strategies:
  - **Base64**: Detects and decodes base64-encoded strings
  - **Hexadecimal**: Identifies hex-encoded data
  - **URL Encoding**: Decodes percent-encoded URLs
  - **ROT13**: Attempts ROT13 cipher decoding
  - **Plain Text**: Extracts readable ASCII/UTF-8 text
- Assigns confidence levels to decoded messages

### 4. Packet Sniffer (`packet_sniffer.py`)
- Coordinates all modules
- Processes each packet through the pipeline
- Displays formatted output
- Maintains packet history and statistics

### 5. Main Application (`main.py`)
- User interface and command-line parsing
- Session management
- Summary reporting

## Example Output

```
================================================================================
Packet #5 - 2026-01-29 10:15:23.456
================================================================================

[Ethernet Frame]
  Source MAC: AA:BB:CC:DD:EE:FF
  Dest MAC: 11:22:33:44:55:66
  Protocol: 8

[IPv4 Packet]
  Source IP: 192.168.1.100
  Dest IP: 93.184.216.34
  Protocol: TCP
  TTL: 64

[TCP Segment]
  Source Port: 54321
  Dest Port: 80
  Sequence: 1234567890
  Acknowledgment: 987654321
  Flags: URG=0 ACK=1 PSH=1 RST=0 SYN=0 FIN=0

********************************************************************************
*** DECODED MESSAGES FOUND ***
********************************************************************************

  [1] Encoding Type: Base64
      Confidence: high
      Original: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzZWNyZXQgbWVzc2FnZQ==...
      Decoded: Hello World! This is a secret message
```

## Security & Legal Considerations

⚠️ **IMPORTANT WARNINGS:**

1. **Permission Required**: Only sniff networks you own or have explicit permission to monitor
2. **Legal Compliance**: Unauthorized packet sniffing may be illegal in your jurisdiction
3. **Privacy**: Be mindful of capturing sensitive information
4. **Root Access**: Tool requires elevated privileges - understand the security implications
5. **Educational Purpose**: This tool is for educational and authorized security testing only

## Limitations

- Requires root/admin privileges for raw socket access
- May not capture all packets on high-traffic networks
- Some encrypted traffic cannot be decoded
- Performance varies by system and network load
- Windows support is limited compared to Linux

## Troubleshooting

### Permission Denied Error
```bash
# Make sure to run with sudo on Linux/Mac
sudo python3 main.py

# On Windows, run Command Prompt as Administrator
```

### No Packets Captured
- Check network interface is active
- Verify you have network traffic
- Try specifying interface explicitly: `--interface eth0`
- Check firewall settings

### Import Errors
- Ensure all .py files are in the same directory
- Verify Python version is 3.6 or higher

## Educational Use Cases

- Learning network protocols and packet structure
- Understanding network security concepts
- Practicing Python socket programming
- Studying encoding and encryption basics
- Network troubleshooting and analysis

## Future Enhancements

Possible additions:
- HTTPS/TLS traffic analysis
- More encoding schemes (Base32, Quoted-Printable, etc.)
- Packet filtering by protocol/port/IP
- Export to PCAP format
- GUI interface
- Real-time statistics dashboard
- IPv6 support
- Deep packet inspection

## License

This is an educational tool. Use responsibly and ethically.

## Contributing

Feel free to enhance the decoder with additional encoding schemes or improve protocol support!

## Disclaimer

This tool is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before monitoring network traffic.