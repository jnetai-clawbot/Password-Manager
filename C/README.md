# Password Manager - C Version

A secure, fast password manager written in C with GTK3 GUI.

## Build

```bash
make
```

Requires: `libssl-dev`, `libsqlite3-dev`

## CLI Usage

```bash
# Initialize (first time)
printf 'password\n' | ./password_manager --init

# Add entry
printf 'password\n' | ./password_manager --add github.com myuser secret123

# Get entry
printf 'password\n' | ./password_manager --get github.com

# List entries (JSON)
printf 'password\n' | ./password_manager --list

# Export/Import (compatible with Python and Android versions)
printf 'password\n' | ./password_manager --export backup.json
printf 'password\n' | ./password_manager --import backup.json

# Generate random password
./password_manager --generate
./password_manager --generate 24
```

## GUI

```bash
cd gui
python3 password_manager_gui.py
```

Features:
- 🔐 Dark themed modern interface
- 🔍 Search functionality  
- 🎲 Password generator
- 📥📤 Import/Export JSON
- 👀 Show/hide passwords
- 📋 Copy to clipboard

## Security

- AES-256-GCM encryption (via OpenSSL)
- PBKDF2 key derivation (100,000 iterations, SHA-256)
- Each entry encrypted with unique salt + nonce
- Master password hash stored (never the password itself)

## File Structure

```
C/
├── password_manager.c    # Main source
├── password_manager      # Compiled binary
├── Makefile
├── gui/
│   ├── password_manager_gui.py   # GTK3 GUI
│   └── password_manager_gui.glade # UI layout
└── README.md
```

## Cross-Compatible

Export/Import JSON format works with:
- Python version
- Android version
