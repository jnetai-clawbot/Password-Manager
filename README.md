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

```
job17/
├── README.md              # This file
├── python/                # Python implementation
│   ├── password_manager.py
│   └── encryption.py
├── C/                     # C implementation
│   ├── password_manager.c
│   └── Makefile
└── android/               # Android app
    └── (via GitHub Actions)
```

## Quick Start

### Python
```bash
cd python
pip install cryptography
python password_manager.py --init
python password_manager.py --add "github.com" "user@example.com" "mypassword123"
python password_manager.py --list
python password_manager.py --get "github.com"
```

### C
```bash
cd C
make
./password_manager --init
./password_manager --add github.com user@example.com mypassword123
./password_manager --list
./password_manager --get github.com
```

### Android
Build via GitHub Actions (see android/ directory)

## Usage

### Python CLI
```bash
# Initialize (first time)
python password_manager.py --init

# Add a password entry
python password_manager.py --add <site> <username> <password>

# List all sites
python password_manager.py --list

# Get password for a site
python password_manager.py --get <site>

# Generate a random password
python password_manager.py --generate 16

# Delete an entry
python password_manager.py --delete <site>

# Export backup
python password_manager.py --export backup.json

# Import backup
python password_manager.py --import backup.json
```

### C CLI
```bash
# Initialize
./password_manager --init

# Add entry
./password_manager --add <site> <username> <password>

# List entries (usernames only)
./password_manager --list

# Get password
./password_manager --get <site>

# Delete entry
./password_manager --delete <site>

# Export/Import
./password_manager --export backup.json
./password_manager --import backup.json
```

## Database Schema

### Sites Table
```sql
CREATE TABLE entries (
    id TEXT PRIMARY KEY,
    site TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    url TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT,
    category TEXT DEFAULT ''
);
```

### Settings Table
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

## API Reference

### Python

```python
from password_manager import PasswordManager

pm = PasswordManager()

# First time setup
pm.setup_master_password("mypassword")

# Verify password
if pm.verify_password("mypassword"):
    print("Access granted")

# Add entry
pm.add_entry("github.com", "user@example.com", "secret123", category="work")

# Get entry
entry = pm.get_entry("github.com")
print(entry['username'], entry['password'])

# List all
for site in pm.list_entries():
    print(site['site'])
```

### C

```c
#include "password_manager.h"

int main() {
    // Initialize
    pm_init("./passwords.db");
    
    // Set master password (first time)
    pm_setup_password("mypassword");
    
    // Verify
    if (pm_verify_password("mypassword")) {
        printf("Access granted\n");
    }
    
    // Add entry
    pm_add_entry("github.com", "user@example.com", "secret123", NULL, NULL);
    
    // List
    PMEntry *entries = NULL;
    int count = pm_list_entries(&entries);
    
    // Get
    PMEntry *entry = pm_get_entry("github.com");
    printf("Username: %s\n", entry->username);
    
    // Cleanup
    pm_free_entries(entries, count);
    pm_close();
}
```

## Requirements

### Python
- Python 3.7+
- cryptography (pip install cryptography)

### C
- GCC/Clang
- OpenSSL (libssl-dev)
- SQLite3 (libsqlite3-dev)

### Android
- Android Studio (or GitHub Actions)
- Gradle 8.4
- API 24+ (Android 7.0+)

## License

MIT License
