#!/usr/bin/env python3
"""
Password Manager - Core Module
Secure password storage with AES-256-GCM encryption
All CLI/GUI/menu versions import from this.
"""

import os
import sys
import json
import hashlib
import secrets
import string
import sqlite3
import getpass
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
DB_PATH = os.path.expanduser("~/.passwords.db")
LOCK_FILE = os.path.expanduser("~/.passwords.lock")
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITER = 10000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes

def get_password_hash(password):
    """Get SHA-256 hash of password"""
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(password, salt):
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(password.encode())

def encrypt(plaintext, password):
    """Encrypt plaintext using AES-256-GCM-SIV"""
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcmsiv = AESGCMSIV(key)
    ciphertext = aesgcmsiv.encrypt(nonce, plaintext.encode(), None)
    return (salt + nonce + ciphertext).hex()

def decrypt(encrypted_hex, password):
    """Decrypt hex-encoded ciphertext"""
    try:
        data = bytes.fromhex(encrypted_hex)
        salt = data[:SALT_LEN]
        nonce = data[SALT_LEN:SALT_LEN+NONCE_LEN]
        ciphertext = data[SALT_LEN+NONCE_LEN:]
        key = derive_key(password, salt)
        aesgcmsiv = AESGCMSIV(key)
        return aesgcmsiv.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return None

def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY, site TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
        password_encrypted TEXT NOT NULL, url TEXT DEFAULT '', notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        category TEXT DEFAULT 'general')''')
    conn.commit()
    conn.close()

def db_get_setting(key):
    """Get a setting from the database"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def db_set_setting(key, value):
    """Set a setting in the database"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def setup_password(password):
    """Set up the master password - returns True if successful, False if already set"""
    if db_get_setting("master_password_hash"):
        return False
    db_set_setting("master_password_hash", get_password_hash(password))
    return True

def verify_password(password):
    """Verify the master password"""
    stored = db_get_setting("master_password_hash")
    return stored == get_password_hash(password)

def reset_db():
    """Delete the database to allow fresh setup"""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        return True
    return False

# Brute force protection
def get_failed_attempts():
    """Get number of failed login attempts"""
    if not os.path.exists(LOCK_FILE):
        return 0
    try:
        with open(LOCK_FILE, 'r') as f:
            data = json.load(f)
            # Check if lockout has expired
            if time.time() - data.get('first_failure', 0) > LOCKOUT_DURATION:
                reset_failed_attempts()
                return 0
            return data.get('attempts', 0)
    except:
        return 0

def record_failed_attempt():
    """Record a failed login attempt"""
    data = {'attempts': 0, 'first_failure': time.time()}
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, 'r') as f:
                data = json.load(f)
        except:
            data = {'attempts': 0, 'first_failure': time.time()}
    
    data['attempts'] = data.get('attempts', 0) + 1
    data['first_failure'] = data.get('first_failure', time.time())
    
    with open(LOCK_FILE, 'w') as f:
        json.dump(data, f)
    
    if data['attempts'] >= MAX_FAILED_ATTEMPTS:
        # Auto-delete database on too many failures
        print(f"[SECURITY] Too many failed attempts ({MAX_FAILED_ATTEMPTS}). Deleting database!")
        reset_db()
        reset_failed_attempts()
        return True  # Indicates database was deleted
    return False

def reset_failed_attempts():
    """Reset failed attempts counter"""
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

def add_entry(site, username, password, master_password, url="", notes="", category="general"):
    """Add a new entry"""
    encrypted = encrypt(password, master_password)
    entry_id = secrets.token_hex(16)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO entries (id, site, username, password_encrypted, url, notes, category)
            VALUES (?, ?, ?, ?, ?, ?, ?)''', (entry_id, site, username, encrypted, url, notes, category))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_entry(site, master_password):
    """Get an entry by site name"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category FROM entries WHERE site = ?''', (site,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    decrypted_password = decrypt(row[2], master_password)
    return {"site": row[0], "username": row[1], "password": decrypted_password,
            "url": row[3], "notes": row[4], "category": row[5]}

def list_entries(master_password):
    """List all entries"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category FROM entries ORDER BY site''')
    rows = c.fetchall()
    conn.close()
    entries = []
    for row in rows:
        decrypted_password = decrypt(row[2], master_password)
        entries.append({"site": row[0], "username": row[1], "password": decrypted_password,
                       "url": row[3], "notes": row[4], "category": row[5]})
    return {"entries": entries}

def delete_entry(site):
    """Delete an entry"""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("DELETE FROM entries WHERE site = ?", (site,))
    conn.commit()
    deleted = c.rowcount > 0
    conn.close()
    return deleted

def update_password(site, new_password, master_password):
    """Update password for an entry"""
    encrypted = encrypt(new_password, master_password)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''UPDATE entries SET password_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE site = ?''', (encrypted, site))
    conn.commit()
    updated = c.rowcount > 0
    conn.close()
    return updated

def update_entry(site, username, password, master_password, url="", notes="", category="general"):
    """Update an existing entry"""
    encrypted = encrypt(password, master_password)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''UPDATE entries SET username = ?, password_encrypted = ?, url = ?, notes = ?, 
                 category = ?, updated_at = CURRENT_TIMESTAMP WHERE site = ?''',
              (username, encrypted, url, notes, category, site))
    conn.commit()
    updated = c.rowcount > 0
    conn.close()
    return updated

def export_json(filename):
    """Export entries to JSON"""
    if not db_get_setting("master_password_hash"):
        return False
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category FROM entries ORDER BY site''')
    rows = c.fetchall()
    conn.close()
    entries = []
    for row in rows:
        entries.append({"site": row[0], "username": row[1], "password": row[2],
                       "url": row[3], "notes": row[4], "category": row[5]})
    with open(filename, 'w') as f:
        json.dump({"entries": entries}, f, indent=2)
    return True

def import_json(filename, master_password):
    """Import entries from JSON"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        count = 0
        for entry in data.get("entries", []):
            site = entry.get("site")
            username = entry.get("username")
            password = entry.get("password")
            if site and username and password:
                try:
                    add_entry(site, username, password, master_password,
                             entry.get("url", ""), entry.get("notes", ""), entry.get("category", "general"))
                    count += 1
                except sqlite3.IntegrityError:
                    pass
        return count
    except Exception:
        return -1

def generate_password(length=16):
    """Generate a random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def print_usage():
    print("""Usage: python3 password_manager.py [OPTIONS]

Options:
  --init              Initialize database with master password
  --reset             Delete database and reset (DANGER! Loses all data!)
  --add SITE USER PASS [URL] [NOTES] [CATEGORY]
                     Add new entry
  --get SITE          Get password for entry
  --list              List all entries (JSON)
  --delete SITE       Delete entry
  --update SITE PASS  Update password for entry
  --export FILE       Export entries to JSON
  --import FILE       Import entries from JSON
  --generate [LEN]    Generate random password (default: 16)
  --gui               Launch GUI version
  --menu              Launch menu version
  --help              Show this help
""")

# CLI Interface
def main():
    init_db()
    
    # Check if locked out
    failed = get_failed_attempts()
    if failed >= MAX_FAILED_ATTEMPTS:
        print(f"[ERROR] Too many failed attempts. Database has been deleted for security.")
        print("[INFO] Run --init to set up a new master password")
        return
    
    args = sys.argv[1:]
    
    # Handle combined args like --password=xxx
    cli_password = None
    new_args = []
    for arg in args:
        if arg.startswith('--password='):
            cli_password = arg.split('=', 1)[1]
        elif arg == '--password' and cli_password is None:
            continue  # Skip, next arg is password
        else:
            new_args.append(arg)
    args = new_args
    
    # Handle --gui and --menu (launch and exit)
    if '--gui' in args:
        args.remove('--gui')
        try:
            from password_manager_gui import main as gui_main
            gui_main()
            return
        except Exception as e:
            print(f"GUI failed: {e}, falling back to menu")
    
    if '--menu' in args:
        args.remove('--menu')
        from password_manager_menu import main as menu_main
        menu_main()
        return
    
    # No args = show help
    if not args or '--help' in args:
        print_usage()
        return
    
    # Handle --reset first (no auth needed)
    if '--reset' in args:
        args.remove('--reset')
        reset_failed_attempts()
        confirm = input("DANGER! This will delete ALL passwords. Type 'yes' to confirm: ")
        if confirm.lower() == 'yes':
            reset_db()
            print("[OK] Database reset. Run --init to set up new master password.")
        else:
            print("[CANCELLED] Reset aborted.")
        return
    
    # Handle --init (no auth needed)
    if '--init' in args:
        args.remove('--init')
        reset_failed_attempts()
        pw = cli_password if cli_password else getpass.getpass("Enter master password: ")
        if len(pw) < 8:
            print("[ERROR] Password must be at least 8 characters")
            return
        if setup_password(pw):
            print("[OK] Master password set up successfully")
        else:
            print("[ERROR] Master password already set up. Use --reset to start over.")
        return
    
    # All other actions require password
    if get_failed_attempts() >= MAX_FAILED_ATTEMPTS:
        print(f"[ERROR] Too many failed attempts. Database deleted for security.")
        return
    
    pw = cli_password if cli_password else getpass.getpass("Enter master password: ")
    if not verify_password(pw):
        deleted = record_failed_attempt()
        remaining = MAX_FAILED_ATTEMPTS - get_failed_attempts()
        if deleted:
            print(f"[SECURITY] Too many failed attempts. Database deleted.")
        else:
            print(f"[ERROR] Invalid master password. {remaining} attempts remaining.")
        return
    
    # Success - reset counter
    reset_failed_attempts()
    
    action = None
    site = username = password = filename = None
    url = notes = category = ""
    
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--add' and i + 3 < len(args):
            action = 'add'
            site, username, password = args[i+1], args[i+2], args[i+3]
            i += 4
        elif arg == '--get' and i + 1 < len(args):
            action, site = 'get', args[i+1]
            i += 2
        elif arg == '--list':
            action, i = 'list', i+1
        elif arg == '--delete' and i + 1 < len(args):
            action, site = 'delete', args[i+1]
            i += 2
        elif arg == '--update' and i + 2 < len(args):
            action, site, password = 'update', args[i+1], args[i+2]
            i += 3
        elif arg == '--export' and i + 1 < len(args):
            action, filename = 'export', args[i+1]
            i += 2
        elif arg == '--import' and i + 1 < len(args):
            action, filename = 'import', args[i+1]
            i += 2
        elif arg == '--generate':
            action = 'generate'
            if i + 1 < len(args) and args[i+1].isdigit():
                action = 'generate_length'
                length = int(args[i+1])
                i += 2
            else:
                i += 1
        else:
            i += 1
    
    if action == 'generate':
        print(generate_password())
    elif action == 'generate_length':
        print(generate_password(length))
    elif action == 'add':
        if add_entry(site, username, password, pw, url, notes, category):
            print(f"[OK] Added entry: {site}")
        else:
            print("[ERROR] Failed to add entry")
    elif action == 'get':
        entry = get_entry(site, pw)
        if entry:
            print(f"\n  Site: {entry['site']}\n  Username: {entry['username']}\n  Password: {entry['password']}\n  URL: {entry['url']}\n")
        else:
            print("[ERROR] Entry not found")
    elif action == 'list':
        print(json.dumps(list_entries(pw), indent=2))
    elif action == 'delete':
        print(f"[OK] Deleted entry: {site}" if delete_entry(site) else "[ERROR] Entry not found")
    elif action == 'update':
        print(f"[OK] Updated password for: {site}" if update_password(site, password, pw) else "[ERROR] Entry not found")
    elif action == 'export':
        print(f"[OK] Exported entries to: {filename}" if export_json(filename) else "[ERROR] Failed to export")
    elif action == 'import':
        count = import_json(filename, pw)
        print(f"[OK] Imported {count} entries from: {filename}" if count >= 0 else "[ERROR] Failed to import")
    else:
        print_usage()

if __name__ == "__main__":
    main()
