# Password Manager - Python Version

Secure password storage with AES-256-GCM encryption.

## Quick Start

```bash
cd /home/jay/Documents/Scripts/AI/openclaw/job17/python

# First time - set up master password
python3 password_manager.py --init

# Or use menu interface (interactive)
python3 password_manager_menu.py

# Or use GUI interface
python3 password_manager_gui.py
```

## Three Interfaces

1. **CLI** (`password_manager.py`) - Command line with arguments
2. **Menu** (`password_manager_menu.py`) - Interactive console menu
3. **GUI** (`password_manager_gui.py`) - Tkinter graphical interface

All three share the same code and database!

## CLI Usage

```bash
# Set up master password
python3 password_manager.py --init --password=YOURPASS

# Add entry
python3 password_manager.py --add github.com username password --password=YOURPASS

# Get password
python3 password_manager.py --get github.com --password=YOURPASS

# List all (JSON)
python3 password_manager.py --list --password=YOURPASS

# Generate random password
python3 password_manager.py --generate

# Export/Import (for backup)
python3 password_manager.py --export backup.json --password=YOURPASS
python3 password_manager.py --import backup.json --password=YOURPASS

# Reset database (deletes everything!)
python3 password_manager.py --reset
```

## Menu Usage

```bash
python3 password_manager_menu.py
```

Interactive menu - just follow the prompts!

## GUI Usage

```bash
python3 password_manager_gui.py
```

Opens a window with buttons for all operations.

## Database

- Location: `~/.passwords.db` (SQLite)
- Uses AES-256-GCM-SIV encryption
- PBKDF2 key derivation (10,000 iterations)

## Reset

If you forget your password, delete the database:
```bash
rm ~/.passwords.db
python3 password_manager.py --init
```
