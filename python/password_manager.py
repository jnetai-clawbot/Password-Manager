"""
Password Manager - Python Implementation
Secure password storage with master password hash verification
"""

import hashlib
import os
import json
import sqlite3
import secrets
import base64
import getpass
from typing import Optional, List, Dict
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography not installed. Run: pip install cryptography")


@dataclass
class PasswordEntry:
    """Represents a password entry"""
    id: str
    site: str
    username: str
    password_encrypted: str  # Encrypted with AES-256-GCM
    url: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""
    category: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at


class Encryption:
    """Handles AES-256-GCM encryption/decryption"""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive 256-bit key from password using PBKDF2"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        """Encrypt data using AES-256-GCM"""
        if not CRYPTO_AVAILABLE:
            return base64.b64encode(plaintext.encode()).decode()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = Encryption.derive_key(password, salt)
        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Combine: salt + nonce + ciphertext
        encrypted = salt + nonce + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_data: str, password: str) -> str:
        """Decrypt AES-256-GCM encrypted data"""
        if not CRYPTO_AVAILABLE:
            return base64.b64decode(encrypted_data.encode()).decode()

        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))

            salt = encrypted_bytes[:16]
            nonce = encrypted_bytes[16:28]
            ciphertext = encrypted_bytes[28:]

            key = Encryption.derive_key(password, salt)
            aesgcm = AESGCM(key)

            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return ""

    @staticmethod
    def hash_password(password: str) -> str:
        """Create SHA-256 hash of password (for verification, NOT encryption)"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against stored hash"""
        return Encryption.hash_password(password) == password_hash


class PasswordManager:
    """Main password manager class"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "passwords.db")
        self.db_path = db_path
        self.master_password_hash: Optional[str] = None
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id TEXT PRIMARY KEY,
                    site TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    url TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    created_at TEXT,
                    updated_at TEXT,
                    category TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.commit()

        # Load master password hash if exists
        self.master_password_hash = self.get_setting("master_password_hash")

    def get_setting(self, key: str) -> Optional[str]:
        """Get a setting value"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            result = cursor.fetchone()
            return result[0] if result else None

    def set_setting(self, key: str, value: str):
        """Set a setting value"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value)
            )
            conn.commit()

    def setup_master_password(self, password: str) -> bool:
        """
        Set up initial master password
        Stores SHA-256 hash of password (NOT the password itself)
        """
        if self.master_password_hash:
            return False  # Already set up

        self.master_password_hash = Encryption.hash_password(password)
        self.set_setting("master_password_hash", self.master_password_hash)
        return True

    def verify_password(self, password: str) -> bool:
        """Verify master password"""
        return Encryption.verify_password(password, self.master_password_hash)

    def is_setup(self) -> bool:
        """Check if master password is configured"""
        return self.master_password_hash is not None

    def add_entry(self, site: str, username: str, password: str,
                  url: str = "", notes: str = "", category: str = "") -> bool:
        """Add a new password entry"""
        if not self.is_setup():
            raise Exception("Master password not set up")

        try:
            encrypted_password = Encryption.encrypt(password, self.master_password_hash)
            entry_id = secrets.token_urlsafe(16)
            now = datetime.now().isoformat()

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO entries 
                    (id, site, username, password_encrypted, url, notes, created_at, updated_at, category)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (entry_id, site, username, encrypted_password, url, notes, now, now, category))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error adding entry: {e}")
            return False

    def get_entry(self, site: str, master_password: str) -> Optional[Dict]:
        """Get a password entry"""
        if not self.verify_password(master_password):
            return None

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM entries WHERE site = ?", (site,))
                row = cursor.fetchone()

                if row:
                    columns = ['id', 'site', 'username', 'password_encrypted', 'url',
                              'notes', 'created_at', 'updated_at', 'category']
                    entry = dict(zip(columns, row))
                    entry['password'] = Encryption.decrypt(
                        entry['password_encrypted'], self.master_password_hash
                    )
                    del entry['password_encrypted']
                    return entry
                return None
        except Exception as e:
            print(f"Error getting entry: {e}")
            return None

    def list_entries(self, master_password: str) -> List[Dict]:
        """List all entries (without decrypted passwords)"""
        if not self.verify_password(master_password):
            return []

        entries = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, site, username, url, category, created_at FROM entries ORDER BY site")
                rows = cursor.fetchall()

                columns = ['id', 'site', 'username', 'url', 'category', 'created_at']
                for row in rows:
                    entries.append(dict(zip(columns, row)))
        except Exception as e:
            print(f"Error listing entries: {e}")
        return entries

    def update_entry(self, site: str, username: str = None, password: str = None,
                    url: str = None, notes: str = None, category: str = None) -> bool:
        """Update an existing entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get current entry
                cursor.execute("SELECT * FROM entries WHERE site = ?", (site,))
                row = cursor.fetchone()
                if not row:
                    return False

                columns = ['id', 'site', 'username', 'password_encrypted', 'url',
                          'notes', 'created_at', 'updated_at', 'category']
                current = dict(zip(columns, row))

                # Update fields
                new_username = username if username is not None else current['username']
                new_url = url if url is not None else current['url']
                new_notes = notes if notes is not None else current['notes']
                new_category = category if category is not None else current['category']

                if password:
                    encrypted_password = Encryption.encrypt(password, self.master_password_hash)
                else:
                    encrypted_password = current['password_encrypted']

                now = datetime.now().isoformat()

                cursor.execute("""
                    UPDATE entries SET
                        username = ?,
                        password_encrypted = ?,
                        url = ?,
                        notes = ?,
                        updated_at = ?,
                        category = ?
                    WHERE site = ?
                """, (new_username, encrypted_password, new_url, new_notes, now, new_category, site))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error updating entry: {e}")
            return False

    def delete_entry(self, site: str) -> bool:
        """Delete an entry"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM entries WHERE site = ?", (site,))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting entry: {e}")
            return False

    def export_json(self, master_password: str) -> str:
        """
        Export all entries as JSON
        
        Format (cross-compatible with Android and C):
        {
            "version": 1,
            "entries": [
                {
                    "site": "github.com",
                    "username": "user@example.com",
                    "password": "secret123",
                    "url": "https://github.com",
                    "notes": "Work account",
                    "category": "work"
                }
            ]
        }
        """
        if not self.verify_password(master_password):
            return "{}"

        entries = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM entries ORDER BY site")
                rows = cursor.fetchall()

                columns = ['id', 'site', 'username', 'password_encrypted', 'url',
                          'notes', 'created_at', 'updated_at', 'category']

                for row in rows:
                    entry = dict(zip(columns, row))
                    entry['password'] = Encryption.decrypt(
                        entry['password_encrypted'], self.master_password_hash
                    )
                    del entry['password_encrypted']
                    del entry['id']
                    del entry['created_at']
                    del entry['updated_at']
                    entries.append(entry)

                export_data = {
                    "version": 1,
                    "app": "password-manager",
                    "entries": entries
                }
                return json.dumps(export_data, indent=2)
        except Exception as e:
            print(f"Export error: {e}")
            return "{}"

    def import_json(self, json_data: str, master_password: str) -> int:
        """
        Import entries from JSON
        
        Supports both old format (array) and new format (object with entries array)
        """
        if not self.verify_password(master_password):
            return 0

        count = 0
        try:
            data = json.loads(json_data)
            
            # Support both formats: {"entries": [...]} or [...]
            if isinstance(data, dict) and "entries" in data:
                entries = data["entries"]
            elif isinstance(data, list):
                entries = data
            else:
                return 0
            
            for item in entries:
                if self.add_entry(
                    item['site'],
                    item['username'],
                    item['password'],
                    item.get('url', ''),
                    item.get('notes', ''),
                    item.get('category', '')
                ):
                    count += 1
        except Exception as e:
            print(f"Import error: {e}")
        return count

    def generate_password(self, length: int = 16) -> str:
        """Generate a random secure password"""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(charset) for _ in range(length))


def main():
    """Command-line interface"""
    import argparse

    parser = argparse.ArgumentParser(description="Password Manager")
    parser.add_argument("--db", default="./passwords.db", help="Database path")
    parser.add_argument("--init", action="store_true", help="Initialize with master password")
    parser.add_argument("--add", nargs=3, metavar=("SITE", "USERNAME", "PASSWORD"),
                       help="Add an entry")
    parser.add_argument("--list", action="store_true", help="List all entries")
    parser.add_argument("--get", metavar="SITE", help="Get password for site")
    parser.add_argument("--update", nargs=2, metavar=("SITE", "NEW_PASSWORD"),
                       help="Update password for site")
    parser.add_argument("--delete", metavar="SITE", help="Delete entry")
    parser.add_argument("--export", metavar="FILE", help="Export to JSON")
    parser.add_argument("--import", dest="import_file", metavar="FILE",
                       help="Import from JSON")
    parser.add_argument("--generate", type=int, metavar="LENGTH",
                       help="Generate random password")
    parser.add_argument("--password", help="Master password")

    args = parser.parse_args()
    pm = PasswordManager(args.db)

    # Handle generate first (no password needed)
    if args.generate:
        print(pm.generate_password(args.generate))
        return

    # Get master password
    if args.password:
        master_password = args.password
    else:
        master_password = getpass.getpass("Master password: ")

    # Initialize
    if args.init:
        confirm = getpass.getpass("Confirm password: ")
        if master_password != confirm:
            print("Passwords don't match")
            return
        if pm.setup_master_password(master_password):
            print("Master password set up successfully")
        else:
            print("Master password already set up")
        return

    # Verify password
    if not pm.verify_password(master_password):
        print("Invalid master password")
        return

    # List entries
    if args.list:
        entries = pm.list_entries(master_password)
        print(f"\nStored entries ({len(entries)}):")
        print("-" * 60)
        for e in entries:
            print(f"  {e['site']}")
            print(f"    Username: {e['username']}")
            if e['url']:
                print(f"    URL: {e['url']}")
            if e['category']:
                print(f"    Category: {e['category']}")
            print()

    # Get entry
    elif args.get:
        entry = pm.get_entry(args.get, master_password)
        if entry:
            print(f"\nSite: {entry['site']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['url']:
                print(f"URL: {entry['url']}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
        else:
            print(f"Entry not found: {args.get}")

    # Add entry
    elif args.add:
        site, username, password = args.add
        if pm.add_entry(site, username, password):
            print(f"Added entry: {site}")
        else:
            print("Failed to add entry")

    # Update entry
    elif args.update:
        site, new_password = args.update
        if pm.update_entry(site, password=new_password):
            print(f"Updated entry: {site}")
        else:
            print("Failed to update entry")

    # Delete entry
    elif args.delete:
        if pm.delete_entry(args.delete):
            print(f"Deleted entry: {args.delete}")
        else:
            print("Failed to delete entry")

    # Export
    elif args.export:
        json_data = pm.export_json(master_password)
        with open(args.export, 'w') as f:
            f.write(json_data)
        print(f"Exported to {args.export}")

    # Import
    elif args.import_file:
        with open(args.import_file, 'r') as f:
            json_data = f.read()
        count = pm.import_json(json_data, master_password)
        print(f"Imported {count} entries")


if __name__ == "__main__":
    main()
