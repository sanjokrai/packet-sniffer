#!/usr/bin/env python3
"""
Main Packet Sniffer Application
Run this file to start the packet sniffer

Usage:
    sudo python3 main.py [--count N] [--interface IFACE]
    
Options:
    --count N        Number of packets to capture (default: 20)
    --interface IFACE Network interface to sniff on (default: auto)
"""

import sys
import argparse
from packet_sniffer import PacketSniffer


def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              NETWORK PACKET SNIFFER & DECODER                 ║
    ║                                                               ║
    ║  Captures network packets and decodes encoded messages        ║
    ║  Supports: Base64, Hex, URL encoding, ROT13, Plain text       ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_usage_info():
    """Print usage information"""
    info = """
    [!] IMPORTANT: This tool requires root/administrator privileges
    
    Linux/Mac:   sudo python3 main.py
    Windows:     Run Command Prompt as Administrator, then: python main.py
    
    [+] The sniffer will:
        1. Capture network packets in real-time
        2. Parse Ethernet, IP, TCP, UDP, and ICMP protocols
        3. Automatically detect and decode encoded messages
        4. Display detailed packet information
    
    [+] Press Ctrl+C to stop capture early
    """
    print(info)


def main():
    """Main application entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer with Message Decoding',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=20,
        help='Number of packets to capture (default: 20)'
    )
    parser.add_argument(
        '--interface', '-i',
        type=str,
        default='',
        help='Network interface to sniff on (default: auto-detect)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode - only show packets with decoded messages'
    )
    
    args = parser.parse_args()
    
    # Print banner and info
    print_banner()
    
    # Check for root privileges
    try:
        import os
        if os.geteuid() != 0:
            print("[!] WARNING: Not running as root. You may need sudo privileges.")
            print("[!] If you encounter permission errors, run with: sudo python3 main.py")
            print()
    except AttributeError:
        # Windows doesn't have geteuid
        pass
    
    print_usage_info()
    
    # Confirm before starting
    try:
        user_input = input("\n[?] Ready to start sniffing? (y/n): ").lower()
        if user_input not in ['y', 'yes']:
            print("[*] Exiting...")
            return
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        return
    
    # Create and start sniffer
    try:
        sniffer = PacketSniffer(interface=args.interface)
        sniffer.start_sniffing(packet_count=args.count, display=True)
        
        # Summary
        print("\n" + "="*80)
        print("CAPTURE SUMMARY")
        print("="*80)
        print(f"Total packets captured: {len(sniffer.get_captured_packets())}")
        print(f"Packets with decoded messages: {len(sniffer.get_decoded_packets())}")
        
        # Show decoded messages summary
        decoded_packets = sniffer.get_decoded_packets()
        if decoded_packets:
            print("\n" + "-"*80)
            print("DECODED MESSAGES SUMMARY")
            print("-"*80)
            for packet in decoded_packets:
                print(f"\nPacket #{packet['number']} - {packet['timestamp']}")
                if packet['ip']:
                    print(f"  {packet['ip']['src_ip']}:{packet['transport'].get('src_port', 'N/A')} -> "
                          f"{packet['ip']['dest_ip']}:{packet['transport'].get('dest_port', 'N/A')}")
                for msg in packet['decoded_messages']:
                    print(f"  [{msg['type']}] {msg['decoded'][:100]}...")
        else:
            print("\n[*] No encoded messages were detected in captured packets")
        
        print("\n[+] Capture session completed successfully!\n")
        
    except PermissionError:
        print("\n[!] ERROR: Permission denied!")
        print("[!] Please run with sudo/administrator privileges:")
        print("    Linux/Mac: sudo python3 main.py")
        print("    Windows: Run as Administrator")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()