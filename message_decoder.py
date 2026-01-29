#!/usr/bin/env python3
"""
Message Decoder Module
Decodes encoded messages from packet payloads
Supports: Base64, Hex, ROT13, URL encoding, and plain text
"""

import base64
import binascii
import urllib.parse
import re


class MessageDecoder:
    @staticmethod
    def decode_payload(data):
        """
        Attempt to decode encoded messages in payload
        Returns a dictionary with decoding results or None
        """
        if not data or len(data) == 0:
            return None
        
        results = []
        
        # Try to decode as UTF-8 first
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = str(data)
        
        # 1. Check for Base64 encoding
        base64_result = MessageDecoder.try_base64(data)
        if base64_result:
            results.append(base64_result)
        
        # 2. Check for Hex encoding
        hex_result = MessageDecoder.try_hex(text)
        if hex_result:
            results.append(hex_result)
        
        # 3. Check for URL encoding
        url_result = MessageDecoder.try_url_decode(text)
        if url_result:
            results.append(url_result)
        
        # 4. Check for ROT13
        rot13_result = MessageDecoder.try_rot13(text)
        if rot13_result:
            results.append(rot13_result)
        
        # 5. Plain text (if printable)
        if MessageDecoder.is_printable(text):
            results.append({
                'type': 'Plain Text',
                'decoded': text[:1000],
                'confidence': 'high' if len(text) > 10 else 'low'
            })
        
        return results if results else None
    
    @staticmethod
    def try_base64(data):
        """Try to decode as Base64"""
        try:
            # Base64 typically has length multiple of 4
            if len(data) % 4 != 0:
                # Try with padding
                padding = 4 - (len(data) % 4)
                data = data + b'=' * padding
            
            decoded = base64.b64decode(data, validate=True)
            decoded_text = decoded.decode('utf-8', errors='ignore')
            
            # Check if decoded content is meaningful
            if MessageDecoder.is_printable(decoded_text) and len(decoded_text) > 3:
                return {
                    'type': 'Base64',
                    'original': data[:100].decode('utf-8', errors='ignore'),
                    'decoded': decoded_text[:1000],
                    'confidence': 'high' if any(c.isalnum() for c in decoded_text) else 'medium'
                }
        except Exception:
            pass
        return None
    
    @staticmethod
    def try_hex(text):
        """Try to decode as Hexadecimal"""
        try:
            # Remove common hex prefixes and whitespace
            cleaned = text.replace('0x', '').replace('\\x', '').replace(' ', '').replace('\n', '')
            
            # Check if it looks like hex
            if re.match(r'^[0-9a-fA-F]+$', cleaned) and len(cleaned) % 2 == 0 and len(cleaned) >= 8:
                decoded = bytes.fromhex(cleaned)
                decoded_text = decoded.decode('utf-8', errors='ignore')
                
                if MessageDecoder.is_printable(decoded_text) and len(decoded_text) > 3:
                    return {
                        'type': 'Hexadecimal',
                        'original': text[:100],
                        'decoded': decoded_text[:1000],
                        'confidence': 'high'
                    }
        except Exception:
            pass
        return None
    
    @staticmethod
    def try_url_decode(text):
        """Try to decode URL encoding"""
        try:
            decoded = urllib.parse.unquote(text)
            
            # Only return if there was actual URL encoding
            if decoded != text and MessageDecoder.is_printable(decoded):
                return {
                    'type': 'URL Encoded',
                    'original': text[:100],
                    'decoded': decoded[:1000],
                    'confidence': 'high' if '%' in text else 'low'
                }
        except Exception:
            pass
        return None
    
    @staticmethod
    def try_rot13(text):
        """Try to decode ROT13"""
        try:
            decoded = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            
            # Only return if decoded text seems more meaningful
            if decoded != text and MessageDecoder.has_english_words(decoded):
                return {
                    'type': 'ROT13',
                    'original': text[:100],
                    'decoded': decoded[:1000],
                    'confidence': 'medium'
                }
        except Exception:
            pass
        return None
    
    @staticmethod
    def is_printable(text):
        """Check if text is printable"""
        if not text:
            return False
        # Allow common printable characters
        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
        return printable_ratio > 0.7
    
    @staticmethod
    def has_english_words(text):
        """Basic check for English words"""
        common_words = ['the', 'and', 'is', 'to', 'in', 'it', 'you', 'that', 'was', 'for']
        text_lower = text.lower()
        return any(word in text_lower for word in common_words)
    
    @staticmethod
    def format_for_display(decoded_results):
        """Format decoded results for display"""
        if not decoded_results:
            return "No decoded messages found"
        
        output = []
        for i, result in enumerate(decoded_results, 1):
            output.append(f"\n  [{i}] Encoding Type: {result['type']}")
            output.append(f"      Confidence: {result['confidence']}")
            if 'original' in result:
                output.append(f"      Original: {result['original']}...")
            output.append(f"      Decoded: {result['decoded']}")
        
        return '\n'.join(output)