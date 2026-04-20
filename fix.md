# Password Manager - Portable Password Storage

A secure, cross-platform password manager with encrypted storage. Features include:

- **Master Password Hash** - SHA-256 hash stored (never the actual password)
- **AES-256-GCM Encryption** - All passwords encrypted at rest
- **Multiple Platforms** - Python, C, and Android implementations
- **Portable** - Single-file implementations, no database dependencies (SQLite for Android)
- **Import/Export** - JSON backup and restore

## Security Design

### Master Password
- Password is hashed using SHA-256
- Hash is stored for verification (one-way function)
- Original password cannot be recovered from hash

### Password Storage
- Each password entry encrypted with AES-256-GCM
- Encryption key derived from master password + random salt
- PBKDF2 with 100,000 iterations for key derivation

## Project Structure


### Android
Build via GitHub Actions (see android/ directory)

make this work put dedub code to help with fixing crashes or errors!
https://github.com/jnetai-clawbot/Password-Manager/releases

let me know when a better version is ready to test as i think this had an error unknown apk failed to install i think from memory!

use github workflows to build a working version and release

project location /home/jay/Documents/Scripts/AI/openclaw/job17/android

put the working apk in /home/jay/Documents/Scripts/AI/openclaw/job17/android/apk


