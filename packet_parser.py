#!/usr/bin/env python3
"""
Packet Parser Module
Parses different protocol layers: Ethernet, IPv4, TCP, UDP
"""

import socket
import struct


class PacketParser:
    @staticmethod
    def parse_ethernet_frame(data):
        """
        Parse Ethernet frame
        Returns: dest_mac, src_mac, protocol, payload
        """
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return (
            PacketParser.format_mac(dest_mac),
            PacketParser.format_mac(src_mac),
            socket.htons(proto),
            data[14:]
        )
    
    @staticmethod
    def format_mac(bytes_addr):
        """Format MAC address to human-readable format"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    @staticmethod
    def parse_ipv4_packet(data):
        """
        Parse IPv4 packet
        Returns: version, header_length, ttl, protocol, src_ip, dest_ip, payload
        """
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return (
            version,
            header_length,
            ttl,
            proto,
            PacketParser.format_ipv4(src),
            PacketParser.format_ipv4(target),
            data[header_length:]
        )
    
    @staticmethod
    def format_ipv4(addr):
        """Format IPv4 address to human-readable format"""
        return '.'.join(map(str, addr))
    
    @staticmethod
    def parse_tcp_segment(data):
        """
        Parse TCP segment
        Returns: src_port, dest_port, sequence, acknowledgment, flags, payload
        """
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack(
            '! H H L L H', data[:14]
        )
        
        offset = (offset_reserved_flags >> 12) * 4
        
        # Extract TCP flags
        flags = {
            'URG': (offset_reserved_flags & 32) >> 5,
            'ACK': (offset_reserved_flags & 16) >> 4,
            'PSH': (offset_reserved_flags & 8) >> 3,
            'RST': (offset_reserved_flags & 4) >> 2,
            'SYN': (offset_reserved_flags & 2) >> 1,
            'FIN': offset_reserved_flags & 1
        }
        
        return (
            src_port,
            dest_port,
            sequence,
            acknowledgment,
            flags,
            data[offset:]
        )
    
    @staticmethod
    def parse_udp_segment(data):
        """
        Parse UDP segment
        Returns: src_port, dest_port, length, payload
        """
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, length, data[8:]
    
    @staticmethod
    def parse_icmp_packet(data):
        """
        Parse ICMP packet
        Returns: type, code, checksum, payload
        """
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]
    
    @staticmethod
    def get_protocol_name(proto_num):
        """Get protocol name from protocol number"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocols.get(proto_num, f'Other({proto_num})')