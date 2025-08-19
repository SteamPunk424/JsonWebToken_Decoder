#!/usr/bin/env python3
import sys
import base64
import json

def decode_jwt_part(part, label=""):
    """Decode a base64url string and try JSON first, fallback to raw bytes"""
    padding = '=' * (-len(part) % 4)
    raw = base64.urlsafe_b64decode(part + padding)
    try:
        return json.loads(raw.decode("utf-8")), "json"
    except Exception:
        # fallback to hex output if not valid JSON
        return raw.hex(), "raw-bytes"

def decode_jwt(token):
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
    except ValueError:
        print("❌ Invalid token format. Must be header.payload.signature")
        sys.exit(1)
    
    header, h_type = decode_jwt_part(header_b64, "header")
    payload, p_type = decode_jwt_part(payload_b64, "payload")
    
    return header, h_type, payload, p_type, signature_b64

def print_usage(prog_name):
    print(f"Usage: {prog_name} <jwt_token>")

def main():
    if len(sys.argv) != 2 or sys.argv[1] == "-h":
        print_usage(sys.argv[0])
        sys.exit(0)

    token = sys.argv[1]
    header, h_type, payload, p_type, signature = decode_jwt(token)

    print("=== Decoded JWT ===")
    print(f"Header ({h_type}): {header}")
    print(f"Payload ({p_type}): {payload}")
    print("Signature (raw base64url):", signature)

if __name__ == "__main__":
    main()

