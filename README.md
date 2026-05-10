# Evidence Decryptor
### Emergency Alerting & Evidence Collection System — v12.0
**Unity University · Faculty of Engineering and Technology · Dept. of Computer Science**

Decrypts AES-256-CBC encrypted audio evidence files (`.enc`) produced by the
ESP32 emergency wearable and plays them back as WAV audio.

---

## Files in this package

```
evidence-decryptor/
├── app.py                  Flask web server (main decryption backend)
├── decrypt_evidence.py     Standalone CLI decryptor (no server needed)
├── requirements.txt        Python dependencies
├── render.yaml             Render.com deployment config
├── templates/
│   └── index.html          Web UI (3 tabs: Decrypt / Verify / Info)
└── README.md               This file
```

---

## Option A — Deploy to Render.com (recommended, free tier)

1. **Create a GitHub repository** and push this entire folder to it

2. Go to **https://render.com** → sign up (free) → **New → Web Service**

3. Connect your GitHub repo

4. Render auto-detects `render.yaml` — click **Deploy**

5. Your app will be live at `https://your-app-name.onrender.com`

> Free tier sleeps after 15 min of inactivity — first load takes ~30s to wake up.
> Upgrade to Starter ($7/mo) for always-on.

---

## Option B — Run locally (Python 3.8+)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
python app.py

# 3. Open browser
open http://localhost:5000
```

---

## Option C — CLI (no server, offline)

```bash
pip install pycryptodome

# Default key + device ID (matches firmware defaults)
python decrypt_evidence.py alert_2026-05-10_140259.enc

# Custom key
python decrypt_evidence.py alert_2026-05-10_140259.enc \
    --key 4A7F3C9E1B5D8A2F6E0C4B7A3D9F1C5E8B2A6D0B4A7E3B9D1A5C8E2B6F0A4C7B \
    --device EMERGENCY_DEVICE_001

# Custom output path
python decrypt_evidence.py alert_2026-05-10_140259.enc --out my_audio.wav
```

---

## Encryption details (matches firmware exactly)

| Parameter     | Value |
|---------------|-------|
| Algorithm     | AES-256-CBC (mbedTLS) |
| Key           | 32 bytes — set via BLE `CHR_AESKEY` or `AES_KEY[]` in firmware |
| IV            | First 16 bytes of `DEVICE_ID`, zero-padded |
| Chunk size    | 1024 bytes per chunk, padded to 16-byte boundary |
| Padding       | PKCS#7 compatible |
| Audio format  | WAV, 8kHz, 8-bit, mono, 30 seconds |
| Integrity     | SHA-256 of `.enc` file stored in `events.txt` |

### Firmware default AES key
```
4A7F3C9E1B5D8A2F6E0C4B7A3D9F1C5E8B2A6D0B4A7E3B9D1A5C8E2B6F0A4C7B
```

### Firmware default Device ID (for IV)
```
EMERGENCY_DEVICE_001
```
IV derived: `EMERGENCY_DEVIC` → `454d455247454e43595f44455649430000`

---

## How to get the .enc file from the device

1. Remove the microSD card from the device after an emergency event
2. Read the card on any computer — files are in the root directory
3. Evidence files are named: `alert_YYYY-MM-DD_HHMMSS.enc`
4. The event log is at `events.txt` — contains SHA-256 hash for verification

---

## Verifying file integrity

The device writes a SHA-256 hash of each `.enc` file to `events.txt`.
Use the **Verify Integrity** tab (or the `/api/verify` endpoint) to confirm
the file has not been modified since it was written by the device.

Example `events.txt` entry:
```
Time:2026-05-10 14:02:59,Dev:EMERGENCY_DEVICE_001,User:Yonatan Amare,
Lat:9.006825,Lng:38.879494,Fix:YES,SMS1:OK,SMS2:OK,Call:ANS,
File:/alert_2026-05-10_140259.enc,SHA256:a3f8b2c1d4e5...
```

---

## Changing the AES key (recommended for production)

1. Generate a new 32-byte random key:
   ```python
   import secrets; print(secrets.token_hex(32))
   ```
2. Set it on the device via BLE → `CHR_AESKEY` characteristic (64 hex chars)
3. Use the same key in the decryptor web UI or `--key` CLI argument
4. Store the key securely — without it, evidence cannot be recovered
