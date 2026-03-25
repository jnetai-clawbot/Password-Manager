#!/usr/bin/env python3
"""
Password Manager - GUI Interface
Tkinter-based graphical interface
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except ImportError:
    print("[ERROR] tkinter not available")
    sys.exit(1)

from password_manager import (
    init_db, verify_password, setup_password, reset_db,
    add_entry, get_entry, list_entries, delete_entry, update_entry,
    update_password, export_json, import_json, generate_password, print_usage, DB_PATH
)

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x500")
        self.current_password = None
        self.entries = []
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.create_widgets()
        self.check_setup()
    
    def check_setup(self):
        """Check if master password is set up"""
        from password_manager import db_get_setting
        if not db_get_setting("master_password_hash"):
            self.show_setup()
        else:
            self.show_login()
    
    def create_widgets(self):
        """Create all widgets"""
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        self.title_label = ttk.Label(self.main_frame, text="Password Manager", 
                                     font=('Arial', 18, 'bold'))
        self.title_label.pack(pady=10)
        
        # Content frame (changes based on state)
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Status bar
        self.status_label = ttk.Label(self.root, text="", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)
    
    def clear_content(self):
        """Clear content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_setup(self):
        """Show first-time setup screen"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Welcome! Set up your master password:",
                 font=('Arial', 12)).pack(pady=20)
        
        ttk.Label(self.content_frame, text="Master Password:").pack(pady=5)
        self.setup_pw = ttk.Entry(self.content_frame, show='*', width=30)
        self.setup_pw.pack(pady=5)
        
        ttk.Label(self.content_frame, text="Confirm Password:").pack(pady=5)
        self.setup_pw2 = ttk.Entry(self.content_frame, show='*', width=30)
        self.setup_pw2.pack(pady=5)
        
        ttk.Label(self.content_frame, text="(Minimum 8 characters)").pack()
        
        ttk.Button(self.content_frame, text="Set Password", 
                  command=self.do_setup).pack(pady=20)
    
    def do_setup(self):
        """Handle setup"""
        pw = self.setup_pw.get()
        pw2 = self.setup_pw2.get()
        
        if not pw:
            messagebox.showerror("Error", "Please enter a password")
            return
        if len(pw) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        if pw != pw2:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        result = setup_password(pw)
        if result:
            self.current_password = pw
            messagebox.showinfo("Success", "Master password has been set!\n\nClick OK to continue.")
            self.show_main_menu()
            self.set_status("[OK] Master password set!")
        else:
            messagebox.showerror("Error", "Failed - database may already have a password.\n\nUse Reset Database to start over.")
    
    def show_login(self):
        """Show login screen"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Enter Master Password:",
                 font=('Arial', 12)).pack(pady=20)
        
        self.login_pw = ttk.Entry(self.content_frame, show='*', width=30)
        self.login_pw.pack(pady=10)
        self.login_pw.bind('<Return>', lambda e: self.do_login())
        
        ttk.Button(self.content_frame, text="Unlock", 
                  command=self.do_login).pack(pady=10)
        
        # Reset button on login screen too
        reset_frame = ttk.Frame(self.content_frame)
        reset_frame.pack(pady=30)
        
        ttk.Label(reset_frame, text="Forgot password?", 
                 foreground='gray').pack()
        ttk.Button(reset_frame, text="Reset Database (DANGER!)",
                  command=self.show_reset).pack(pady=5)
    
    def do_login(self):
        """Handle login"""
        pw = self.login_pw.get()
        if verify_password(pw):
            self.current_password = pw
            self.show_main_menu()
            self.set_status("[OK] Logged in")
        else:
            messagebox.showerror("Error", "Invalid password")
            self.login_pw.delete(0, tk.END)
    
    def show_reset(self):
        """Show reset confirmation"""
        # Clear and show reset screen
        self.clear_content()
        
        ttk.Label(self.content_frame, text="DANGER!", 
                 font=('Arial', 16, 'bold'), foreground='red').pack(pady=20)
        ttk.Label(self.content_frame, text="This will delete ALL passwords!",
                 font=('Arial', 12)).pack(pady=10)
        ttk.Label(self.content_frame, text="Type 'yes' to confirm:").pack(pady=10)
        
        self.reset_confirm = ttk.Entry(self.content_frame, width=20)
        self.reset_confirm.pack(pady=10)
        
        ttk.Button(self.content_frame, text="RESET DATABASE", 
                  command=self.do_reset_confirm,
                  style='Danger.TButton').pack(pady=20)
        
        ttk.Button(self.content_frame, text="Close", 
                  command=self.show_main_menu).pack(pady=5)
    
    def do_reset_confirm(self):
        """Handle reset confirmation"""
        confirm = self.reset_confirm.get().strip()
        if confirm.lower() == 'yes':
            reset_db()
            self.current_password = None
            self.show_setup()
            self.set_status("[OK] Database reset - please set new password")
        else:
            messagebox.showwarning("Cancelled", "Database not reset")
            self.show_main_menu()
    
    def show_main_menu(self):
        """Show main menu when logged in"""
        self.clear_content()
        
        # Buttons grid
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(expand=True)
        
        buttons = [
            ("Add Entry", self.show_add_entry),
            ("Get Password", self.show_get_password),
            ("List All Entries", self.show_list),
            ("Update Password", self.show_update),
            ("Delete Entry", self.show_delete),
            ("Generate Password", self.show_generate),
            ("Export to JSON", self.show_export),
            ("Import from JSON", self.show_import),
            ("Lock (Logout)", self.do_lock),
            ("About", self.show_about),
        ]
        
        for i, (text, cmd) in enumerate(buttons):
            btn = ttk.Button(btn_frame, text=text, command=cmd, width=20)
            btn.grid(row=i//2, column=i%2, padx=10, pady=5)
    
    def show_add_entry(self):
        """Show add entry form"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Add New Entry", 
                 font=('Arial', 14)).pack(pady=10)
        
        form = ttk.Frame(self.content_frame)
        form.pack(pady=10)
        
        fields = ['Site', 'Username', 'Password', 'URL', 'Notes']
        self.add_entries = {}
        
        for i, field in enumerate(fields):
            ttk.Label(form, text=f"{field}:").grid(row=i, column=0, sticky=tk.W, pady=5)
            entry = ttk.Entry(form, width=35)
            if field == 'Password':
                entry.insert(0, generate_password())
            entry.grid(row=i, column=1, pady=5, padx=5)
            self.add_entries[field.lower()] = entry
        
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Save", command=self.do_add_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Back", command=self.show_main_menu).pack(side=tk.LEFT, padx=5)
    
    def do_add_entry(self):
        """Save new entry"""
        site = self.add_entries['site'].get().strip()
        username = self.add_entries['username'].get().strip()
        password = self.add_entries['password'].get().strip()
        url = self.add_entries['url'].get().strip()
        notes = self.add_entries['notes'].get().strip()
        
        if site and username and password:
            if add_entry(site, username, password, self.current_password, url, notes):
                messagebox.showinfo("OK", f"Added {site}")
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Failed to add entry")
        else:
            messagebox.showerror("Error", "Site, username, password required")
    
    def show_get_password(self):
        """Show get password form"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Get Password", 
                 font=('Arial', 14)).pack(pady=10)
        
        form = ttk.Frame(self.content_frame)
        form.pack(pady=10)
        
        ttk.Label(form, text="Site:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.get_site = ttk.Entry(form, width=35)
        self.get_site.grid(row=0, column=1, pady=5, padx=5)
        self.get_site.bind('<Return>', lambda e: self.do_get_password())
        
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Get", command=self.do_get_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Back", command=self.show_main_menu).pack(side=tk.LEFT, padx=5)
    
    def do_get_password(self):
        """Get and display password"""
        site = self.get_site.get().strip()
        entry = get_entry(site, self.current_password)
        
        if entry:
            self.clear_content()
            ttk.Label(self.content_frame, text=entry['site'], 
                     font=('Arial', 14, 'bold')).pack(pady=5)
            
            details = [
                ("Username", entry['username']),
                ("Password", entry['password']),
                ("URL", entry['url']),
                ("Category", entry['category']),
            ]
            
            for label, value in details:
                if value:
                    ttk.Label(self.content_frame, text=f"{label}: {value}",
                             font=('Arial', 11)).pack(pady=2)
            
            ttk.Button(self.content_frame, text="Back", 
                      command=self.show_main_menu).pack(pady=20)
        else:
            messagebox.showerror("Error", "Entry not found")
    
    def show_list(self):
        """Show all entries with search/filter"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="All Entries", 
                 font=('Arial', 14)).pack(pady=5)
        
        # Search/filter bar
        search_frame = ttk.Frame(self.content_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', lambda e: self.filter_entries())
        
        # Category filter
        ttk.Label(search_frame, text="Category:").pack(side=tk.LEFT, padx=5)
        self.category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, 
                                           values=['All'], width=15, state='readonly')
        self.category_combo.pack(side=tk.LEFT, padx=5)
        self.category_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_entries())
        
        # Results label
        self.results_label = ttk.Label(self.content_frame, text="")
        self.results_label.pack(pady=2)
        
        # Treeview frame
        list_frame = ttk.Frame(self.content_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview
        columns = ('Username', 'URL', 'Category')
        self.entries_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings')
        self.entries_tree.heading('#0', text='Site')
        self.entries_tree.heading('Username', text='Username')
        self.entries_tree.heading('URL', text='URL')
        self.entries_tree.heading('Category', text='Category')
        self.entries_tree.column('#0', width=150)
        self.entries_tree.column('Username', width=120)
        self.entries_tree.column('URL', width=180)
        self.entries_tree.column('Category', width=80)
        self.entries_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind double-click to edit
        self.entries_tree.bind('<Double-1>', lambda e: self.edit_selected_entry())
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.entries_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)
        
        # Load all entries
        result = list_entries(self.current_password)
        self.all_entries = result.get('entries', [])
        
        # Populate category filter
        categories = sorted(set(e.get('category', 'general') or 'general' for e in self.all_entries))
        self.category_combo['values'] = ['All'] + categories
        
        # Populate tree
        self.filter_entries()
        
        # Buttons
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Edit Selected", command=self.edit_selected_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Refresh", command=self.show_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Back", command=self.show_main_menu).pack(side=tk.LEFT, padx=5)
    
    def filter_entries(self):
        """Filter entries based on search and category"""
        search = self.search_var.get().lower()
        category = self.category_var.get()
        
        # Clear tree
        for item in self.entries_tree.get_children():
            self.entries_tree.delete(item)
        
        filtered = []
        for e in self.all_entries:
            # Category filter
            if category != 'All' and e.get('category', 'general') != category:
                continue
            
            # Search filter
            if search:
                site = e.get('site', '').lower()
                username = e.get('username', '').lower()
                url = e.get('url', '').lower()
                if search not in site and search not in username and search not in url:
                    continue
            
            filtered.append(e)
            self.entries_tree.insert('', tk.END, text=e['site'],
                                    values=(e.get('username', ''), 
                                           e.get('url', ''), 
                                           e.get('category', 'general')),
                                    tags=(e['site'],))
        
        self.results_label.config(text=f"Showing {len(filtered)} of {len(self.all_entries)} entries")
    
    def edit_selected_entry(self):
        """Edit the selected entry"""
        selection = self.entries_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to edit")
            return
        
        item = selection[0]
        site = self.entries_tree.item(item, 'text')
        
        # Get full entry data
        entry = get_entry(site, self.current_password)
        if not entry:
            messagebox.showerror("Error", "Entry not found")
            return
        
        self.show_edit_entry(entry)
    
    def show_edit_entry(self, entry):
        """Show edit form for an entry"""
        self.clear_content()
        self.current_edit_site = entry['site']  # Store original site name
        
        ttk.Label(self.content_frame, text=f"Edit Entry: {entry['site']}", 
                 font=('Arial', 14)).pack(pady=10)
        
        form = ttk.Frame(self.content_frame)
        form.pack(pady=10)
        
        fields = [
            ('Site', entry['site']),
            ('Username', entry['username']),
            ('Password', entry['password']),
            ('URL', entry.get('url', '')),
            ('Notes', entry.get('notes', '')),
            ('Category', entry.get('category', 'general')),
        ]
        
        self.edit_entries = {}
        for i, (field, value) in enumerate(fields):
            ttk.Label(form, text=f"{field}:").grid(row=i, column=0, sticky=tk.W, pady=5)
            
            if field == 'Notes':
                # Text widget for notes
                text = tk.Text(form, width=35, height=4)
                text.insert('1.0', value or '')
                text.grid(row=i, column=1, pady=5, padx=5)
                self.edit_entries[field.lower()] = text
            elif field == 'Category':
                # Combobox for category
                combo = ttk.Combobox(form, values=['general', 'work', 'personal', 'finance', 'social'], 
                                   width=33, state='readonly')
                combo.set(value or 'general')
                combo.grid(row=i, column=1, pady=5, padx=5)
                self.edit_entries[field.lower()] = combo
            else:
                entry_widget = ttk.Entry(form, width=35)
                entry_widget.insert(0, value or '')
                entry_widget.grid(row=i, column=1, pady=5, padx=5)
                self.edit_entries[field.lower()] = entry_widget
        
        # Password generator
        gen_frame = ttk.Frame(form)
        gen_frame.grid(row=3, column=1, sticky='w', pady=2)
        
        ttk.Label(gen_frame, text="Generate:").pack(side=tk.LEFT)
        self.gen_length = ttk.Spinbox(gen_frame, from_=8, to=64, width=5)
        self.gen_length.set(16)
        self.gen_length.pack(side=tk.LEFT, padx=5)
        ttk.Button(gen_frame, text="New Password", command=self.generate_new_password).pack(side=tk.LEFT)
        
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Save Changes", command=self.do_edit_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.show_list).pack(side=tk.LEFT, padx=5)
    
    def generate_new_password(self):
        """Generate new password into the password field"""
        length = int(self.gen_length.get())
        new_password = generate_password(length)
        self.edit_entries['password'].delete(0, tk.END)
        self.edit_entries['password'].insert(0, new_password)
    
    def do_edit_entry(self):
        """Save edited entry"""
        site = self.edit_entries['site'].get().strip()
        username = self.edit_entries['username'].get().strip()
        password = self.edit_entries['password'].get().strip()
        url = self.edit_entries['url'].get().strip()
        notes = self.edit_entries['notes'].get('1.0', tk.END).strip()
        category = self.edit_entries['category'].get().strip() or 'general'
        
        if not site or not username or not password:
            messagebox.showerror("Error", "Site, username, and password required")
            return
        
        # Use update_entry which handles existing entries
        if update_entry(site, username, password, self.current_password, url, notes, category):
            messagebox.showinfo("Success", f"Updated {site}")
            self.show_list()
        else:
            messagebox.showerror("Error", "Failed to update entry")
    
    def delete_selected_entry(self):
        """Delete the selected entry"""
        selection = self.entries_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to delete")
            return
        
        item = selection[0]
        site = self.entries_tree.item(item, 'text')
        
        if messagebox.askyesno("Confirm Delete", f"Delete entry for '{site}'?"):
            if delete_entry(site):
                messagebox.showinfo("Deleted", f"Deleted {site}")
                self.show_list()
            else:
                messagebox.showerror("Error", "Failed to delete")
    
    def show_update(self):
        """Show update password form"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Update Password", 
                 font=('Arial', 14)).pack(pady=10)
        
        form = ttk.Frame(self.content_frame)
        form.pack(pady=10)
        
        ttk.Label(form, text="Site:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.update_site = ttk.Entry(form, width=35)
        self.update_site.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(form, text="New Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.update_pw = ttk.Entry(form, width=35)
        self.update_pw.grid(row=1, column=1, pady=5, padx=5)
        self.update_pw.insert(0, generate_password())
        
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Update", command=self.do_update).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Back", command=self.show_main_menu).pack(side=tk.LEFT, padx=5)
    
    def do_update(self):
        """Update password"""
        site = self.update_site.get().strip()
        password = self.update_pw.get().strip()
        
        if site and password:
            if update_password(site, password, self.current_password):
                messagebox.showinfo("OK", f"Updated {site}")
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Entry not found")
        else:
            messagebox.showerror("Error", "Site and password required")
    
    def show_delete(self):
        """Show delete form"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Delete Entry", 
                 font=('Arial', 14)).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Enter site name to delete:").pack(pady=10)
        
        self.delete_site = ttk.Entry(self.content_frame, width=35)
        self.delete_site.pack(pady=10)
        
        btn_frame = ttk.Frame(self.content_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Delete", command=self.do_delete).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Back", command=self.show_main_menu).pack(side=tk.LEFT, padx=5)
    
    def do_delete(self):
        """Delete entry"""
        site = self.delete_site.get().strip()
        
        if messagebox.askyesno("Confirm", f"Delete {site}?"):
            if delete_entry(site):
                messagebox.showinfo("OK", f"Deleted {site}")
                self.show_main_menu()
            else:
                messagebox.showerror("Error", "Entry not found")
    
    def show_generate(self):
        """Show generate password"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Generate Password", 
                 font=('Arial', 14)).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Length:").pack()
        
        self.gen_length = ttk.Spinbox(self.content_frame, from_=8, to=64, width=10)
        self.gen_length.set(16)
        self.gen_length.pack(pady=10)
        
        ttk.Button(self.content_frame, text="Generate", 
                  command=self.do_generate).pack(pady=5)
        
        self.gen_result = ttk.Label(self.content_frame, text="", font=('Courier', 12))
        self.gen_result.pack(pady=10)
        
        ttk.Button(self.content_frame, text="Back", 
                  command=self.show_main_menu).pack(pady=10)
    
    def do_generate(self):
        """Generate and display password"""
        length = int(self.gen_length.get())
        password = generate_password(length)
        self.gen_result.config(text=password)
    
    def show_export(self):
        """Show export dialog"""
        filename = simpledialog.askstring("Export", "Enter filename:")
        if filename:
            if export_json(filename):
                messagebox.showinfo("OK", f"Exported to {filename}")
            else:
                messagebox.showerror("Error", "Export failed")
    
    def show_import(self):
        """Show import dialog"""
        filename = simpledialog.askstring("Import", "Enter filename:")
        if filename:
            count = import_json(filename, self.current_password)
            if count >= 0:
                messagebox.showinfo("OK", f"Imported {count} entries")
            else:
                messagebox.showerror("Error", "Import failed")
    
    def do_lock(self):
        """Lock the manager"""
        self.current_password = None
        self.show_login()
        self.set_status("[OK] Locked")
    
    def show_about(self):
        """Show about dialog"""
        self.clear_content()
        
        ttk.Label(self.content_frame, text="Password Manager", 
                 font=('Arial', 18, 'bold')).pack(pady=20)
        
        ttk.Label(self.content_frame, text="Version 1.0", 
                 font=('Arial', 12)).pack(pady=5)
        
        ttk.Label(self.content_frame, text="Secure password storage", 
                 font=('Arial', 10)).pack(pady=5)
        
        ttk.Label(self.content_frame, text="━━━━━━━━━━━━━━━━━━━━━", 
                 font=('Arial', 10)).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Created By J~Net 2026", 
                 font=('Arial', 11, 'bold')).pack(pady=5)
        
        ttk.Label(self.content_frame, text="Site: jnetai.com", 
                 font=('Arial', 10)).pack(pady=5)
        
        ttk.Label(self.content_frame, text="━━━━━━━━━━━━━━━━━━━━━", 
                 font=('Arial', 10)).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Built with Python & Tkinter", 
                 font=('Arial', 9), foreground='gray').pack(pady=5)
        
        ttk.Button(self.content_frame, text="Back", 
                  command=self.show_main_menu).pack(pady=20)
    
    def set_status(self, message):
        """Set status bar message"""
        self.status_label.config(text=message)

def main():
    init_db()
    
    # Check if we have a display
    import os
    has_display = os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')
    
    if not has_display:
        print("[INFO] No display detected, launching menu interface...")
        print("[INFO] For GUI, run with X server (e.g., VNC or HDMI)")
        print()
        from password_manager_menu import main as menu_main
        menu_main()
        return
    
    try:
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"[ERROR] GUI failed: {e}")
        print("[INFO] Falling back to menu...")
        from password_manager_menu import main as menu_main
        menu_main()

if __name__ == "__main__":
    main()
