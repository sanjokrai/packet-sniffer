#!/usr/bin/env python3
"""
Packet Capture Module
Handles raw socket creation and packet capture
"""

import socket
import struct


class PacketCapture:
    def __init__(self, interface=''):
        """Initialize packet capture"""
        self.interface = interface
        self.socket = None
        
    def create_socket(self):
        """Create a raw socket for packet capture - requires root/admin privileges"""
        try:
            # Linux: AF_PACKET for raw ethernet frames
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            print("[+] Socket created successfully (Linux mode)")
            return self.socket
        except AttributeError:
            # Windows/Mac: Different approach
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.socket.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                # Enable promiscuous mode on Windows
                try:
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except:
                    pass
                    
                print("[+] Socket created successfully (Windows/Mac mode)")
                return self.socket
            except Exception as e:
                print(f"[-] Error creating socket: {e}")
                raise
        except PermissionError:
            print("[-] Permission denied. Please run with sudo/administrator privileges.")
            raise
    
    def capture_packet(self):
        """Capture a single packet"""
        if not self.socket:
            raise Exception("Socket not initialized. Call create_socket() first.")
        
        raw_data, addr = self.socket.recvfrom(65536)
        return raw_data
    
    def close(self):
        """Close the socket"""
        if self.socket:
            try:
                # Disable promiscuous mode on Windows
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
            self.socket.close()
            print("\n[+] Socket closed")