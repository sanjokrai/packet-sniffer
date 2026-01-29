#!/usr/bin/env python3
"""
Packet Sniffer Module
Main sniffer class that coordinates packet capture, parsing, and decoding
"""

import textwrap
from datetime import datetime
from packet_capture import PacketCapture
from packet_parser import PacketParser
from message_decoder import MessageDecoder


class PacketSniffer:
    def __init__(self, interface=''):
        """Initialize the packet sniffer"""
        self.interface = interface
        self.packet_count = 0
        self.capture = PacketCapture(interface)
        self.parser = PacketParser()
        self.decoder = MessageDecoder()
        self.captured_packets = []
        
    def format_multi_line(self, prefix, string, size=80):
        """Format multi-line output"""
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
    def process_packet(self, raw_data):
        """Process a single packet"""
        self.packet_count += 1
        packet_info = {
            'number': self.packet_count,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'ethernet': {},
            'ip': {},
            'transport': {},
            'payload': None,
            'decoded_messages': []
        }
        
        # Parse Ethernet frame
        try:
            dest_mac, src_mac, eth_proto, data = self.parser.parse_ethernet_frame(raw_data)
            packet_info['ethernet'] = {
                'dest_mac': dest_mac,
                'src_mac': src_mac,
                'protocol': eth_proto
            }
            
            # IPv4 packets
            if eth_proto == 8:
                version, header_length, ttl, proto, src_ip, dest_ip, data = self.parser.parse_ipv4_packet(data)
                packet_info['ip'] = {
                    'version': version,
                    'header_length': header_length,
                    'ttl': ttl,
                    'protocol': proto,
                    'protocol_name': self.parser.get_protocol_name(proto),
                    'src_ip': src_ip,
                    'dest_ip': dest_ip
                }
                
                # TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flags, data = self.parser.parse_tcp_segment(data)
                    packet_info['transport'] = {
                        'type': 'TCP',
                        'src_port': src_port,
                        'dest_port': dest_port,
                        'sequence': sequence,
                        'acknowledgment': acknowledgment,
                        'flags': flags
                    }
                    packet_info['payload'] = data
                
                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = self.parser.parse_udp_segment(data)
                    packet_info['transport'] = {
                        'type': 'UDP',
                        'src_port': src_port,
                        'dest_port': dest_port,
                        'length': length
                    }
                    packet_info['payload'] = data
                
                # ICMP
                elif proto == 1:
                    icmp_type, code, checksum, data = self.parser.parse_icmp_packet(data)
                    packet_info['transport'] = {
                        'type': 'ICMP',
                        'icmp_type': icmp_type,
                        'code': code,
                        'checksum': checksum
                    }
                    packet_info['payload'] = data
                
                # Try to decode payload
                if packet_info['payload']:
                    decoded = self.decoder.decode_payload(packet_info['payload'])
                    if decoded:
                        packet_info['decoded_messages'] = decoded
        
        except Exception as e:
            packet_info['error'] = str(e)
        
        self.captured_packets.append(packet_info)
        return packet_info
    
    def display_packet(self, packet_info):
        """Display packet information"""
        print(f"\n{'='*80}")
        print(f"Packet #{packet_info['number']} - {packet_info['timestamp']}")
        print(f"{'='*80}")
        
        # Ethernet info
        if packet_info['ethernet']:
            eth = packet_info['ethernet']
            print(f"\n[Ethernet Frame]")
            print(f"  Source MAC: {eth['src_mac']}")
            print(f"  Dest MAC: {eth['dest_mac']}")
            print(f"  Protocol: {eth['protocol']}")
        
        # IP info
        if packet_info['ip']:
            ip = packet_info['ip']
            print(f"\n[IPv4 Packet]")
            print(f"  Source IP: {ip['src_ip']}")
            print(f"  Dest IP: {ip['dest_ip']}")
            print(f"  Protocol: {ip['protocol_name']}")
            print(f"  TTL: {ip['ttl']}")
        
        # Transport layer info
        if packet_info['transport']:
            trans = packet_info['transport']
            print(f"\n[{trans['type']} Segment]")
            
            if trans['type'] == 'TCP':
                print(f"  Source Port: {trans['src_port']}")
                print(f"  Dest Port: {trans['dest_port']}")
                print(f"  Sequence: {trans['sequence']}")
                print(f"  Acknowledgment: {trans['acknowledgment']}")
                flags_str = ' '.join([f"{k}={v}" for k, v in trans['flags'].items()])
                print(f"  Flags: {flags_str}")
            
            elif trans['type'] == 'UDP':
                print(f"  Source Port: {trans['src_port']}")
                print(f"  Dest Port: {trans['dest_port']}")
                print(f"  Length: {trans['length']}")
            
            elif trans['type'] == 'ICMP':
                print(f"  Type: {trans['icmp_type']}")
                print(f"  Code: {trans['code']}")
        
        # Decoded messages
        if packet_info['decoded_messages']:
            print(f"\n{'*'*80}")
            print(f"*** DECODED MESSAGES FOUND ***")
            print(f"{'*'*80}")
            print(self.decoder.format_for_display(packet_info['decoded_messages']))
        elif packet_info['payload'] and len(packet_info['payload']) > 0:
            print(f"\n[Payload Preview]")
            preview = packet_info['payload'][:100]
            print(self.format_multi_line('  ', preview))
        
        if 'error' in packet_info:
            print(f"\n[Error] {packet_info['error']}")
    
    def start_sniffing(self, packet_count=10, display=True):
        """Start sniffing packets"""
        print(f"\n{'='*80}")
        print(f"PACKET SNIFFER STARTED")
        print(f"Capturing {packet_count} packets...")
        print(f"{'='*80}")
        
        try:
            self.capture.create_socket()
            
            for i in range(packet_count):
                raw_data = self.capture.capture_packet()
                packet_info = self.process_packet(raw_data)
                
                if display:
                    self.display_packet(packet_info)
            
            print(f"\n{'='*80}")
            print(f"Capture complete! Total packets: {self.packet_count}")
            print(f"{'='*80}\n")
            
        except KeyboardInterrupt:
            print("\n\n[!] Capture interrupted by user")
        except Exception as e:
            print(f"\n[!] Error during capture: {e}")
        finally:
            self.capture.close()
    
    def get_captured_packets(self):
        """Return all captured packets"""
        return self.captured_packets
    
    def get_decoded_packets(self):
        """Return only packets with decoded messages"""
        return [p for p in self.captured_packets if p['decoded_messages']]