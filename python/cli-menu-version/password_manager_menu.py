#!/usr/bin/env python3
"""
Password Manager - Menu Interface
Interactive console menu version
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from password_manager import (
    init_db, verify_password, setup_password, reset_db,
    add_entry, get_entry, list_entries, delete_entry, update_password,
    export_json, import_json, generate_password, print_usage
)

def clear_screen():
    import shutil
    shutil.rmpipe = lambda: None  # Suppress warnings
    os.system('cls' if os.name == 'nt' else 'clear 2>/dev/null || true')

def get_master_password():
    """Get master password from user"""
    import getpass
    return getpass.getpass("Master password: ")

def main():
    init_db()
    current_password = None
    
    while True:
        clear_screen()
        print("=" * 50)
        print("     PASSWORD MANAGER - Menu")
        print("=" * 50)
        
        if current_password is None:
            print("\n1. Set up new master password")
            print("2. Unlock with master password")
            print("3. Reset database (DANGER!)")
            print("4. Help / CLI options")
            print("5. Exit")
            print("\n* You must set up or unlock to view passwords *")
        else:
            print(f"\n* Logged in *")
            print("1. Add new entry")
            print("2. Get password")
            print("3. List all entries")
            print("4. Update password")
            print("5. Delete entry")
            print("6. Generate password")
            print("7. Export to JSON")
            print("8. Import from JSON")
            print("9. Lock (logout)")
            print("10. Exit")
        
        print("\n" + "=" * 50)
        
        choice = input("Choice: ").strip()
        
        if current_password is None:
            if choice == '1':  # Setup
                clear_screen()
                print("Set up new master password")
                print("(Minimum 8 characters)")
                pw = input("Enter master password: ")
                if len(pw) < 8:
                    input("Password too short! Press Enter...")
                    continue
                pw2 = input("Confirm password: ")
                if pw != pw2:
                    input("Passwords don't match! Press Enter...")
                    continue
                if setup_password(pw):
                    current_password = pw
                    input("[OK] Master password set! Press Enter...")
                else:
                    input("[ERROR] Already set up. Use reset first. Press Enter...")
            
            elif choice == '2':  # Unlock
                clear_screen()
                print("Unlock Password Manager")
                pw = get_master_password()
                if verify_password(pw):
                    current_password = pw
                    input("[OK] Unlocked! Press Enter...")
                else:
                    input("[ERROR] Invalid password! Press Enter...")
            
            elif choice == '3':  # Reset
                clear_screen()
                print("DANGER! This will delete ALL passwords!")
                confirm = input("Type 'yes' to confirm: ")
                if confirm.lower() == 'yes':
                    reset_db()
                    current_password = None
                    input("[OK] Database reset! Press Enter...")
                else:
                    input("[CANCELLED] Press Enter...")
            
            elif choice == '4':  # Help
                clear_screen()
                print_usage()
                input("\nPress Enter to continue...")
            
            elif choice == '5':  # Exit
                print("Goodbye!")
                sys.exit(0)
            else:
                input("Invalid choice! Press Enter...")
        
        else:
            # Logged in menu
            if choice == '1':  # Add
                clear_screen()
                print("Add New Entry")
                site = input("Site name: ").strip()
                username = input("Username: ").strip()
                password = input("Password: ").strip()
                url = input("URL (optional): ").strip()
                notes = input("Notes (optional): ").strip()
                category = input("Category [general]: ").strip() or "general"
                if site and username and password:
                    if add_entry(site, username, password, current_password, url, notes, category):
                        input(f"[OK] Added {site}! Press Enter...")
                    else:
                        input("[ERROR] Failed! Press Enter...")
                else:
                    input("Site, username, password required! Press Enter...")
            
            elif choice == '2':  # Get
                clear_screen()
                print("Get Password")
                site = input("Site name: ").strip()
                entry = get_entry(site, current_password)
                if entry:
                    print(f"\nSite: {entry['site']}")
                    print(f"Username: {entry['username']}")
                    print(f"Password: {entry['password']}")
                    if entry['url']:
                        print(f"URL: {entry['url']}")
                    if entry['notes']:
                        print(f"Notes: {entry['notes']}")
                else:
                    print("[ERROR] Entry not found!")
                input("\nPress Enter to continue...")
            
            elif choice == '3':  # List
                clear_screen()
                print("All Entries")
                result = list_entries(current_password)
                if result['entries']:
                    for e in result['entries']:
                        print(f"  {e['site']} | {e['username']} | {e['category']}")
                else:
                    print("(No entries)")
                input("\nPress Enter to continue...")
            
            elif choice == '4':  # Update
                clear_screen()
                print("Update Password")
                site = input("Site name: ").strip()
                new_pass = input("New password: ").strip()
                if site and new_pass:
                    if update_password(site, new_pass, current_password):
                        input(f"[OK] Updated {site}! Press Enter...")
                    else:
                        input("[ERROR] Entry not found! Press Enter...")
                else:
                    input("Site and password required! Press Enter...")
            
            elif choice == '5':  # Delete
                clear_screen()
                print("Delete Entry")
                site = input("Site name to delete: ").strip()
                confirm = input(f"Delete {site}? Type 'yes' to confirm: ")
                if confirm.lower() == 'yes':
                    if delete_entry(site):
                        input(f"[OK] Deleted {site}! Press Enter...")
                    else:
                        input("[ERROR] Entry not found! Press Enter...")
                else:
                    input("[CANCELLED]")
            
            elif choice == '6':  # Generate
                clear_screen()
                print("Generate Password")
                length = input("Length [16]: ").strip()
                length = int(length) if length.isdigit() else 16
                password = generate_password(length)
                print(f"\nGenerated: {password}")
                input("\nPress Enter to continue...")
            
            elif choice == '7':  # Export
                clear_screen()
                print("Export to JSON")
                filename = input("Filename: ").strip()
                if filename:
                    if export_json(filename):
                        input(f"[OK] Exported to {filename}! Press Enter...")
                    else:
                        input("[ERROR] Export failed! Press Enter...")
                else:
                    input("Filename required! Press Enter...")
            
            elif choice == '8':  # Import
                clear_screen()
                print("Import from JSON")
                filename = input("Filename: ").strip()
                if filename:
                    count = import_json(filename, current_password)
                    if count >= 0:
                        input(f"[OK] Imported {count} entries! Press Enter...")
                    else:
                        input("[ERROR] Import failed! Press Enter...")
                else:
                    input("Filename required! Press Enter...")
            
            elif choice == '9':  # Lock
                current_password = None
                input("[OK] Locked! Press Enter...")
            
            elif choice == '10':  # Exit
                print("Goodbye!")
                sys.exit(0)
            else:
                input("Invalid choice! Press Enter...")

if __name__ == "__main__":
    main()
