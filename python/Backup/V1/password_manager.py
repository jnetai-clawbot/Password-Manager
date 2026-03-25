#!/usr/bin/env python3
"""
Password Manager - Python Version
Secure password storage with AES-256-GCM encryption
"""

import os
import sys
import json
import hashlib
import secrets
import string
import sqlite3
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
DB_PATH = os.path.expanduser("~/.passwords.db")
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITER = 10000

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
    
    # Combine: salt + nonce + ciphertext
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        site TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        password_encrypted TEXT NOT NULL,
        url TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        category TEXT DEFAULT 'general'
    )''')
    conn.commit()
    conn.close()
    return True

def db_get_setting(key):
    """Get a setting from the database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def db_set_setting(key, value):
    """Set a setting in the database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def setup_password(password):
    """Set up the master password"""
    if db_get_setting("master_password_hash"):
        return False  # Already set up
    db_set_setting("master_password_hash", get_password_hash(password))
    return True

def verify_password(password):
    """Verify the master password"""
    stored = db_get_setting("master_password_hash")
    return stored == get_password_hash(password)

def add_entry(site, username, password, master_password, url="", notes="", category="general"):
    """Add a new entry"""
    encrypted = encrypt(password, master_password)
    entry_id = secrets.token_hex(16)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO entries 
        (id, site, username, password_encrypted, url, notes, category)
        VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (entry_id, site, username, encrypted, url, notes, category))
    conn.commit()
    conn.close()
    return True

def get_entry(site, master_password):
    """Get an entry by site name"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category 
        FROM entries WHERE site = ?''', (site,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return None
    
    decrypted_password = decrypt(row[2], master_password)
    return {
        "site": row[0],
        "username": row[1],
        "password": decrypted_password,
        "url": row[3],
        "notes": row[4],
        "category": row[5]
    }

def list_entries(master_password):
    """List all entries (with decrypted passwords)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category 
        FROM entries ORDER BY site''')
    rows = c.fetchall()
    conn.close()
    
    entries = []
    for row in rows:
        decrypted_password = decrypt(row[2], master_password)
        entries.append({
            "site": row[0],
            "username": row[1],
            "password": decrypted_password,
            "url": row[3],
            "notes": row[4],
            "category": row[5]
        })
    return {"entries": entries}

def delete_entry(site):
    """Delete an entry by site name"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM entries WHERE site = ?", (site,))
    conn.commit()
    deleted = c.rowcount > 0
    conn.close()
    return deleted

def update_password(site, new_password, master_password):
    """Update the password for an entry"""
    encrypted = encrypt(new_password, master_password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''UPDATE entries SET password_encrypted = ?, updated_at = CURRENT_TIMESTAMP
        WHERE site = ?''', (encrypted, site))
    conn.commit()
    updated = c.rowcount > 0
    conn.close()
    return updated

def export_json(filename):
    """Export entries to JSON file"""
    if not db_get_setting("master_password_hash"):
        return False
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT site, username, password_encrypted, url, notes, category 
        FROM entries ORDER BY site''')
    rows = c.fetchall()
    conn.close()
    
    entries = []
    for row in rows:
        entries.append({
            "site": row[0],
            "username": row[1],
            "password": row[2],  # Already encrypted hex
            "url": row[3],
            "notes": row[4],
            "category": row[5]
        })
    
    with open(filename, 'w') as f:
        json.dump({"entries": entries}, f, indent=2)
    return True

def import_json(filename, master_password):
    """Import entries from JSON file"""
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        count = 0
        for entry in data.get("entries", []):
            site = entry.get("site")
            username = entry.get("username")
            password = entry.get("password")  # Already encrypted
            
            if site and username and password:
                try:
                    # Verify we can decrypt it (optional)
                    add_entry(site, username, password, master_password,
                             entry.get("url", ""), entry.get("notes", ""),
                             entry.get("category", "general"))
                    count += 1
                except sqlite3.IntegrityError:
                    pass  # Site already exists
        
        return count
    except Exception as e:
        return -1

def generate_password(length=16):
    """Generate a random password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

def print_usage():
    print("""Usage: python3 password_manager.py [OPTIONS]

Options:
  --init              Initialize database with master password
  --add SITE USER PASS [URL] [NOTES] [CATEGORY]
                     Add new entry
  --get SITE          Get password for entry
  --list              List all entries (JSON)
  --delete SITE       Delete entry
  --update SITE PASS  Update password for entry
  --export FILE       Export entries to JSON
  --import FILE       Import entries from JSON
  --generate [LEN]    Generate random password (default: 16)
  --help              Show this help
""")

def main():
    init_db()
    
    args = sys.argv[1:]
    if not args or "--help" in args:
        print_usage()
        return
    
    action = None
    site = None
    username = None
    password = None
    filename = None
    url = ""
    notes = ""
    category = "general"
    
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--init":
            action = "init"
        elif arg == "--add" and i + 3 < len(args):
            action = "add"
            site = args[i + 1]
            username = args[i + 2]
            password = args[i + 3]
            i += 4
            if i < len(args) and not args[i].startswith("--"):
                url = args[i]; i += 1
            if i < len(args) and not args[i].startswith("--"):
                notes = args[i]; i += 1
            if i < len(args) and not args[i].startswith("--"):
                category = args[i]; i += 1
        elif arg == "--get" and i + 1 < len(args):
            action = "get"
            site = args[i + 1]
            i += 2
        elif arg == "--list":
            action = "list"
            i += 1
        elif arg == "--delete" and i + 1 < len(args):
            action = "delete"
            site = args[i + 1]
            i += 2
        elif arg == "--update" and i + 2 < len(args):
            action = "update"
            site = args[i + 1]
            password = args[i + 2]
            i += 3
        elif arg == "--export" and i + 1 < len(args):
            action = "export"
            filename = args[i + 1]
            i += 2
        elif arg == "--import" and i + 1 < len(args):
            action = "import"
            filename = args[i + 1]
            i += 2
        elif arg == "--generate":
            action = "generate"
            if i + 1 < len(args) and args[i + 1].isdigit():
                action = "generate_length"
                length = int(args[i + 1])
                i += 2
            else:
                i += 1
        else:
            i += 1
    
    # Handle --password option
    cli_password = None
    if "--password" in args:
        idx = args.index("--password")
        if idx + 1 < len(args):
            cli_password = args[idx + 1]
    
    # Generate password (no auth needed)
    if action == "generate":
        print(generate_password())
        return
    if action == "generate_length":
        print(generate_password(length))
        return
    
    # Init (no auth needed)
    if action == "init":
        pw = cli_password if cli_password else getpass.getpass("Enter master password: ")
        if len(pw) < 8:
            print("[ERROR] Password must be at least 8 characters")
            return
        if setup_password(pw):
            print("[OK] Master password set up successfully")
        else:
            print("[ERROR] Master password already set up")
        return
    
    # All other actions require password
    pw = cli_password if cli_password else getpass.getpass("Enter master password: ")
    
    if not verify_password(pw):
        print("[ERROR] Invalid master password")
        return
    
    if action == "add":
        if add_entry(site, username, password, pw, url, notes, category):
            print(f"[OK] Added entry: {site}")
        else:
            print("[ERROR] Failed to add entry")
    elif action == "get":
        entry = get_entry(site, pw)
        if entry:
            print(f"\n  Site: {entry['site']}")
            print(f"  Username: {entry['username']}")
            print(f"  Password: {entry['password']}")
            if entry['url']:
                print(f"  URL: {entry['url']}")
            print()
        else:
            print("[ERROR] Entry not found")
    elif action == "list":
        result = list_entries(pw)
        print(json.dumps(result, indent=2))
    elif action == "delete":
        if delete_entry(site):
            print(f"[OK] Deleted entry: {site}")
        else:
            print("[ERROR] Entry not found")
    elif action == "update":
        if update_password(site, password, pw):
            print(f"[OK] Updated password for: {site}")
        else:
            print("[ERROR] Failed to update entry")
    elif action == "export":
        if export_json(filename):
            print(f"[OK] Exported entries to: {filename}")
        else:
            print("[ERROR] Failed to export entries")
    elif action == "import":
        count = import_json(filename, pw)
        if count >= 0:
            print(f"[OK] Imported {count} entries from: {filename}")
        else:
            print("[ERROR] Failed to import entries")
    else:
        print_usage()

if __name__ == "__main__":
    main()
