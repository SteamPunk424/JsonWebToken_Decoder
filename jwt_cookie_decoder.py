#!/usr/bin/env python3
import sys
import base64
import json
import zlib

def b64url_decode(part: str) -> bytes:
    """Base64url decode with proper padding."""
    padding = '=' * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + padding)

def try_zlib_decompress(data: bytes):
    """Try zlib/deflate decompression; return decompressed bytes or None."""
    try:
        return zlib.decompress(data)
    except Exception:
        return None

def decode_part(part_b64: str):
    """
    Decode a base64url part, try zlib decompression, then JSON parse,
    finally fall back to raw bytes (hex).
    Returns (value, kind) where kind is 'zlib+json', 'zlib+raw', 'json', 'raw-bytes'.
    """
    try:
        raw = b64url_decode(part_b64)
    except Exception as e:
        return (f"<base64-decode-error: {e}>", "invalid-base64")

    # try zlib decompress first (many itsdangerous payloads start with zlib)
    decompressed = try_zlib_decompress(raw)
    if decompressed is not None:
        # try parse JSON
        try:
            return (json.loads(decompressed.decode('utf-8')), "zlib+json")
        except Exception:
            return (decompressed, "zlib+raw")

    # not compressed, try JSON directly
    try:
        return (json.loads(raw.decode('utf-8')), "json")
    except Exception:
        return (raw, "raw-bytes")

def looks_like_jwt_header(obj):
    """Heuristic: header as JSON typically has 'alg' or 'typ' keys."""
    if isinstance(obj, dict):
        if 'alg' in obj or 'typ' in obj:
            return True
    return False

def decode_token(token: str):
    # split and handle leading dot (Flask/itsdangerous)
    parts = token.split('.')
    if parts and parts[0] == '':
        parts = parts[1:]

    if len(parts) == 0:
        raise SystemExit("❌ Empty token after stripping leading dot.")

    # If there are exactly 3 parts, it *might* be JWT (header.payload.signature)
    # but some cookies are payload.sig1.sig2 — detect by inspecting decoded first part.
    if len(parts) == 3:
        first_decoded, first_type = decode_part(parts[0])
        if first_type in ("json", "zlib+json") and looks_like_jwt_header(first_decoded):
            # Treat as header.payload.signature (classic JWT)
            header, h_type = first_decoded, first_type
            payload, p_type = decode_part(parts[1])
            signature = parts[2]
            return {"format": "jwt", "header": (header, h_type), "payload": (payload, p_type), "signature_parts": [signature]}
        else:
            # Treat as payload + two signature parts (itsdangerous-style)
            payload, p_type = (first_decoded, first_type)
            sig_parts = parts[1:]
            return {"format": "payload-first", "payload": (payload, p_type), "signature_parts": sig_parts}

    # If 2 parts: could be payload.signature or header.payload (rare). Assume payload.signature.
    if len(parts) == 2:
        payload, p_type = decode_part(parts[0])
        signature = parts[1]
        return {"format": "payload-signature", "payload": (payload, p_type), "signature_parts": [signature]}

    # If more than 3 parts, commonly payload + multiple sig parts — decode the first as payload.
    if len(parts) > 3:
        payload, p_type = decode_part(parts[0])
        sig_parts = parts[1:]
        return {"format": "payload-multi-sig", "payload": (payload, p_type), "signature_parts": sig_parts}

    # fallback (shouldn't normally reach)
    raise SystemExit("❌ Unexpected token format.")

def pretty_print(result):
    fmt = result.get("format")

    if fmt == "jwt":
        header, h_type = result["header"]
        payload, p_type = result["payload"]
        sigs = result["signature_parts"]
        print("=== Detected format: JWT (header.payload.signature) ===")
        print(f"Header ({h_type}):")
        print_json_or_bytes(header)
        print(f"\nPayload ({p_type}):")
        print_json_or_bytes(payload)
        print(f"\nSignature (raw base64url): {sigs[0]}")
    else:
        payload, p_type = result["payload"]
        sigs = result["signature_parts"]
        print(f"=== Detected format: {fmt} ===")
        print(f"Payload ({p_type}):")
        print_json_or_bytes(payload)
        print(f"\nSignature parts ({len(sigs)}):")
        for i, s in enumerate(sigs, 1):
            print(f"  [{i}] {s}")

def print_json_or_bytes(x):
    if isinstance(x, dict):
        print(json.dumps(x, indent=2))
    elif isinstance(x, (bytes, bytearray)):
        # show beginning of raw bytes and hex fallback
        try:
            txt = x.decode('utf-8')
            print(txt)
        except Exception:
            # binary: show hex
            h = x.hex()
            preview = h[:160] + ("..." if len(h) > 160 else "")
            print(f"<raw-bytes hex (preview)> {preview}")
    else:
        print(repr(x))

def usage(prog):
    print(f"Usage: {prog} <token>")
    print("Accepts JWTs and Flask/itsdangerous-style cookies (leading dot, zlib-compressed payloads).")

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        usage(sys.argv[0])
        sys.exit(0)

    token = sys.argv[1].strip()
    try:
        result = decode_token(token)
    except SystemExit as e:
        print(e)
        sys.exit(1)

    pretty_print(result)

if __name__ == "__main__":
    main()
