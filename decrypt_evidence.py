#!/usr/bin/env python3
"""
decrypt_evidence.py — Standalone CLI decryptor
Emergency Alerting & Evidence Collection System v12.0
Unity University — Faculty of Engineering and Technology

Usage:
    python decrypt_evidence.py <file.enc> [options]

Options:
    --key     64-char hex AES-256 key (default: firmware default key)
    --device  Device ID string for IV derivation (default: EMERGENCY_DEVICE_001)
    --out     Output WAV path (default: <file>_decrypted.wav)

Examples:
    # Using firmware default key and device ID:
    python decrypt_evidence.py alert_2026-05-10_140259.enc

    # Using custom key:
    python decrypt_evidence.py alert_2026-05-10_140259.enc \\
        --key 4A7F3C9E1B5D8A2F6E0C4B7A3D9F1C5E8B2A6D0B4A7E3B9D1A5C8E2B6F0A4C7B \\
        --device EMERGENCY_DEVICE_001

pip install pycryptodome
"""

import sys
import os
import struct
import hashlib
import argparse
from Crypto.Cipher import AES

# ── Firmware default AES key (from firmware source) ─────────────────────────
DEFAULT_KEY_HEX = (
    "4A7F3C9E1B5D8A2F6E0C4B7A3D9F1C5E"
    "8B2A6D0B4A7E3B9D1A5C8E2B6F0A4C7B"
)
DEFAULT_DEVICE_ID = "EMERGENCY_DEVICE_001"


def hex_to_bytes(hex_str: str) -> bytes:
    hex_str = hex_str.strip().replace(' ', '').replace('0x', '').replace(',', '')
    if len(hex_str) != 64:
        raise ValueError(f"AES key must be 64 hex chars, got {len(hex_str)}")
    return bytes.fromhex(hex_str)


def device_id_to_iv(device_id: str) -> bytes:
    """Match firmware: iv[i] = (uint8_t)DEVICE_ID[i], zero-padded to 16."""
    return device_id.encode('ascii', errors='replace')[:16].ljust(16, b'\x00')


def decrypt_evidence(enc_data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(enc_data) % 16 != 0:
        raise ValueError(
            f"File length {len(enc_data)} is not a multiple of 16. "
            "File may be truncated or corrupt."
        )
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc_data)
    # Strip firmware padding (same as PKCS#7)
    pad = dec[-1]
    if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]):
        dec = dec[:-pad]
    return dec


def build_wav(pcm: bytes, sr=8000, ch=1, bits=8) -> bytes:
    if pcm[:4] == b'RIFF' and pcm[8:12] == b'WAVE':
        # Read actual bit depth and channels from existing header
        if len(pcm) >= 36:
            bits = struct.unpack_from('<H', pcm, 34)[0]
            ch   = struct.unpack_from('<H', pcm, 22)[0]
        # Extract raw PCM from data chunk
        i = 12
        while i < len(pcm) - 8:
            chunk_id   = pcm[i:i+4]
            chunk_size = struct.unpack_from('<I', pcm, i+4)[0]
            if chunk_id == b'data':
                pcm = pcm[i+8:]
                break
            i += 8 + chunk_size

    n  = len(pcm)
    br = sr * ch * bits // 8
    ba = ch * bits // 8
    hdr  = struct.pack('<4sI4s', b'RIFF', 36 + n, b'WAVE')
    hdr += struct.pack('<4sIHHIIHH', b'fmt ', 16, 1, ch, sr, br, ba, bits)
    hdr += struct.pack('<4sI', b'data', n)
    return hdr + pcm

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt emergency evidence .enc files to WAV audio'
    )
    parser.add_argument('enc_file', help='Path to .enc file from SD card')
    parser.add_argument('--key',    default=DEFAULT_KEY_HEX,
                        help='64-char hex AES-256 key (default: firmware default)')
    parser.add_argument('--device', default=DEFAULT_DEVICE_ID,
                        help='Device ID for IV derivation (default: EMERGENCY_DEVICE_001)')
    parser.add_argument('--out',    default=None,
                        help='Output WAV path (default: <input>_decrypted.wav)')
    args = parser.parse_args()

    enc_path = args.enc_file
    if not os.path.exists(enc_path):
        print(f"[ERROR] File not found: {enc_path}")
        sys.exit(1)

    out_path = args.out or os.path.splitext(enc_path)[0] + '_decrypted.wav'

    print(f"\n{'='*55}")
    print(f"  Emergency Evidence Decryptor")
    print(f"  Unity University — Dept. of Computer Science")
    print(f"{'='*55}")
    print(f"  Input  : {enc_path}")
    print(f"  Output : {out_path}")
    print(f"  Device : {args.device}")
    print(f"  Key    : {args.key[:8]}...{args.key[-8:]}")

    try:
        key = hex_to_bytes(args.key)
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    iv = device_id_to_iv(args.device)
    print(f"  IV     : {iv.hex()}")

    print(f"\n  Reading encrypted file...")
    with open(enc_path, 'rb') as f:
        enc_data = f.read()
    enc_sha = hashlib.sha256(enc_data).hexdigest()
    print(f"  Encrypted size : {len(enc_data):,} bytes")
    print(f"  SHA-256 (enc)  : {enc_sha}")

    print(f"\n  Decrypting (AES-256-CBC)...")
    try:
        pcm = decrypt_evidence(enc_data, key, iv)
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        sys.exit(1)

    print(f"  Decrypted size : {len(pcm):,} bytes")

      wav = build_wav(pcm, sr=8000)
    with open(out_path, 'wb') as f:
        f.write(wav)

    wav_sha = sha256_file(out_path)

    # Estimate duration
    actual_bits = struct.unpack_from('<H', wav, 34)[0]
    duration = len(pcm) / (8000 * (actual_bits // 8))
    print(f"\n  WAV written    : {out_path}")
    print(f"  Duration       : {duration:.1f} seconds")
    print(f"  Bit depth      : {actual_bits}-bit")
    print(f"  SHA-256 (wav)  : {wav_sha}")
    print(f"\n  Done. Open {out_path} in any audio player.")
    print(f"{'='*55}\n")


if __name__ == '__main__':
    main()
