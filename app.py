"""
Emergency Evidence Decryption Server
Unity University — Faculty of Engineering and Technology

Decrypts AES-256-CBC encrypted audio evidence files
produced by the Emergency Alerting & Evidence Collection System (v12.0)

Encryption scheme (from firmware):
  - AES-256-CBC, mbedTLS
  - IV: first 16 bytes of DEVICE_ID (zero-padded)
  - Key: 32-byte AES_KEY (set via BLE or hardcoded in firmware)
  - Padding: PKCS#7-style (custom: pad byte = pad length, full block)
  - Chunk size: 1024 bytes → padded to next 16-byte boundary
  - Output: raw encrypted bytes, no header
  - Source WAV: 8kHz, 8-bit, mono, PCM
"""

import os
import io
import hashlib
import struct
from flask import Flask, request, jsonify, send_file, render_template
from Crypto.Cipher import AES

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB max upload

UPLOAD_FOLDER = '/tmp/evidence_uploads'
OUTPUT_FOLDER = '/tmp/evidence_output'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert 64-char hex string to 32 bytes (AES key format from firmware)."""
    hex_str = hex_str.strip().replace(' ', '').replace('0x', '').replace(',', '')
    if len(hex_str) != 64:
        raise ValueError(f"AES key must be 64 hex characters (32 bytes), got {len(hex_str)}")
    return bytes.fromhex(hex_str)


def device_id_to_iv(device_id: str) -> bytes:
    """
    Reproduce firmware IV derivation:
      for (int i = 0; i < 16 && DEVICE_ID[i]; i++) iv[i] = (uint8_t)DEVICE_ID[i];
    First 16 bytes of DEVICE_ID string, zero-padded to 16 bytes.
    """
    id_bytes = device_id.encode('ascii', errors='replace')[:16]
    return id_bytes.ljust(16, b'\x00')


def decrypt_evidence(enc_data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-256-CBC encrypted evidence file.

    Firmware encrypts in 1024-byte chunks, each padded to 16-byte boundary.
    The padding scheme: pad_byte = (padded_size - original_size), fills remainder.
    This matches standard PKCS#7 for the last chunk; intermediate chunks are
    always padded to the next 16-byte multiple of min(chunk, 1024).

    We decrypt the whole file as one CBC stream (IV chains across chunks)
    then strip trailing padding from the last block.
    """
    if len(enc_data) == 0:
        raise ValueError("Encrypted file is empty")
    if len(enc_data) % 16 != 0:
        raise ValueError(f"Encrypted data length {len(enc_data)} is not a multiple of 16 — file may be corrupt")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc_data)

    # Strip padding from last block
    # Firmware: pad byte = (padded_size - real_size), same value repeated
    pad_byte = decrypted[-1]
    if 1 <= pad_byte <= 16:
        # Validate padding
        if all(b == pad_byte for b in decrypted[-pad_byte:]):
            decrypted = decrypted[:-pad_byte]

    return decrypted


def build_wav_header(pcm_data: bytes, sample_rate: int = 8000,
                     channels: int = 1, bits_per_sample: int = 8) -> bytes:
    """
    Build a standard WAV header for the decrypted PCM data.
    Firmware records: 8kHz, 8-bit, mono — these are the defaults.
    If the decrypted data already has a RIFF header, it's returned as-is.
    """
    # Check if already a valid WAV (firmware writes WAV before encrypting)
    if pcm_data[:4] == b'RIFF' and pcm_data[8:12] == b'WAVE':
        return pcm_data  # already a complete WAV file

    # Build WAV header around raw PCM
    data_size = len(pcm_data)
    byte_rate = sample_rate * channels * bits_per_sample // 8
    block_align = channels * bits_per_sample // 8

    header = struct.pack('<4sI4s', b'RIFF', 36 + data_size, b'WAVE')
    header += struct.pack('<4sIHHIIHH', b'fmt ', 16, 1, channels,
                         sample_rate, byte_rate, block_align, bits_per_sample)
    header += struct.pack('<4sI', b'data', data_size)
    return header + pcm_data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """
    POST /api/decrypt
    Form fields:
      file      — .enc file upload
      aes_key   — 64 hex chars (32 bytes)
      device_id — device ID string (used to derive IV)
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    aes_key_hex = request.form.get('aes_key', '').strip()
    device_id = request.form.get('device_id', '').strip()

    if not f.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not aes_key_hex:
        return jsonify({'error': 'AES key is required'}), 400
    if not device_id:
        return jsonify({'error': 'Device ID is required'}), 400

    # Validate and parse key
    try:
        aes_key = hex_to_bytes(aes_key_hex)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    # Derive IV from device ID
    iv = device_id_to_iv(device_id)

    # Read encrypted data
    enc_data = f.read()
    enc_sha256 = sha256_hex(enc_data)
    enc_size = len(enc_data)

    # Decrypt
    try:
        decrypted = decrypt_evidence(enc_data, aes_key, iv)
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400

    # Wrap in WAV if needed
    wav_data = build_wav_header(decrypted)
    wav_sha256 = sha256_hex(wav_data)

    # Save output
    base_name = os.path.splitext(f.filename)[0]
    out_filename = f"{base_name}_decrypted.wav"
    out_path = os.path.join(OUTPUT_FOLDER, out_filename)
    with open(out_path, 'wb') as out:
        out.write(wav_data)

    # Estimate duration
    # WAV: data chunk size / (sample_rate * channels * bits/8)
    duration_s = 0
    if wav_data[:4] == b'RIFF':
        try:
            data_offset = wav_data.find(b'data')
            if data_offset > 0:
                data_size = struct.unpack_from('<I', wav_data, data_offset + 4)[0]
                duration_s = data_size / 8000  # 8kHz, 8-bit, mono = 8000 bytes/s
        except Exception:
            pass

    return jsonify({
        'success': True,
        'filename': out_filename,
        'enc_size_bytes': enc_size,
        'dec_size_bytes': len(wav_data),
        'duration_seconds': round(duration_s, 1),
        'enc_sha256': enc_sha256,
        'wav_sha256': wav_sha256,
        'iv_hex': iv.hex(),
        'key_preview': aes_key_hex[:8] + '...' + aes_key_hex[-8:],
    })


@app.route('/api/download/<filename>')
def download(filename):
    """Download decrypted WAV file."""
    # Sanitize filename — no path traversal
    filename = os.path.basename(filename)
    path = os.path.join(OUTPUT_FOLDER, filename)
    if not os.path.exists(path):
        return jsonify({'error': 'File not found — it may have expired'}), 404
    return send_file(path, as_attachment=True,
                     download_name=filename,
                     mimetype='audio/wav')


@app.route('/api/verify', methods=['POST'])
def verify_hash():
    """
    POST /api/verify
    Verify a file's SHA-256 against the hash recorded in events.txt
    Form fields: file, expected_hash
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    f = request.files['file']
    expected = request.form.get('expected_hash', '').strip().lower()
    data = f.read()
    actual = sha256_hex(data)
    match = (actual == expected) if expected else None
    return jsonify({
        'actual_sha256': actual,
        'expected_sha256': expected or None,
        'match': match,
        'file_size': len(data),
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
