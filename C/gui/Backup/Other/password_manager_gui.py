#!/usr/bin/env python3
"""J~Net Password Manager - GTK3 GUI (Dark Theme)
Simple programmatic UI - no Glade required
"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib
import os
import sys
import subprocess
import json

BIN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "password_manager")

class PasswordManagerGUI:
    def __init__(self):
        self.window = Gtk.Window()
        self.window.set_title("Password Manager")
        self.window.set_default_size(800, 500)
        self.window.connect("destroy", Gtk.main_quit)
        
        self.apply_css()
        
        self.stack = Gtk.Stack()
        self.window.add(self.stack)
        
        self.login_view()
        self.main_view()
        
        self.unlocked = False
        self.master_password = None
        self.current_entry = None
        self.all_entries = []
        
        self.window.show_all()
    
    def apply_css(self):
        css = """
        window { background-color: #1e1e2e; }
        entry { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a; padding: 8px; border-radius: 4px; }
        button { background-color: #89b4fa; color: #1e1e2e; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; }
        button:hover { background-color: #b4befe; }
        button.danger { background-color: #f38ba8; }
        button.secondary { background-color: #585b70; color: #cdd6f4; }
        treeview { background-color: #313244; color: #cdd6f4; }
        label { color: #cdd6f4; }
        headerbar { background-color: #181825; }
        """
        style_provider = Gtk.CssProvider()
        style_provider.load_from_data(css.encode())
        Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), style_provider, 600)
    
    def login_view(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_halign(Gtk.Align.CENTER)
        box.set_valign(Gtk.Align.CENTER)
        box.set_margin_top(40)
        box.set_margin_bottom(40)
        box.set_margin_start(40)
        box.set_margin_end(40)
        
        box.pack_start(Gtk.Label(label="🔐 Password Manager", visible=True), False, False, 0)
        box.pack_start(Gtk.Label(label="Enter master password", visible=True), False, False, 0)
        
        self.password_entry = Gtk.Entry()
        self.password_entry.set_placeholder_text("Password")
        self.password_entry.set_visibility(False)
        self.password_entry.set_width_chars(30)
        self.password_entry.connect("activate", self.on_unlock)
        box.pack_start(self.password_entry, False, False, 0)
        
        self.password_entry2 = Gtk.Entry()
        self.password_entry2.set_placeholder_text("Confirm Password")
        self.password_entry2.set_visibility(False)
        self.password_entry2.set_width_chars(30)
        box.pack_start(self.password_entry2, False, False, 0)
        
        self.login_status = Gtk.Label()
        self.login_status.set_markup('<span foreground="#f38ba8"></span>')
        box.pack_start(self.login_status, False, False, 0)
        
        btn_box = Gtk.Box(spacing=12)
        unlock_btn = Gtk.Button(label="Unlock")
        unlock_btn.connect("clicked", self.on_unlock)
        init_btn = Gtk.Button(label="Initialize")
        init_btn.connect("clicked", self.on_init)
        btn_box.pack_start(unlock_btn, False, False, 0)
        btn_box.pack_start(init_btn, False, False, 0)
        box.pack_start(btn_box, False, False, 0)
        
        self.stack.add_named(box, "login")
    
    def main_view(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Header
        header = Gtk.HeaderBar()
        header.set_title("Password Manager")
        header.set_show_close_button(True)
        
        lock_btn = Gtk.Button(label="🔒 Lock")
        lock_btn.connect("clicked", self.on_lock)
        header.pack_start(lock_btn)
        
        export_btn = Gtk.Button(label="📤 Export")
        export_btn.connect("clicked", self.on_export)
        header.pack_end(export_btn)
        
        import_btn = Gtk.Button(label="📥 Import")
        import_btn.connect("clicked", self.on_import)
        header.pack_end(import_btn)
        
        vbox.pack_start(header, False, False, 0)
        
        # Toolbar
        toolbar = Gtk.Toolbar()
        toolbar.set_hexpand(True)
        
        add_btn = Gtk.ToolButton.new(None, label="Add")
        add_btn.connect("clicked", self.on_add)
        toolbar.insert(add_btn, -1)
        
        edit_btn = Gtk.ToolButton.new(None, label="Edit")
        edit_btn.connect("clicked", self.on_edit)
        toolbar.insert(edit_btn, -1)
        
        delete_btn = Gtk.ToolButton.new(None, label="Delete")
        delete_btn.connect("clicked", self.on_delete)
        toolbar.insert(delete_btn, -1)
        
        copy_btn = Gtk.ToolButton.new(None, label="Copy")
        copy_btn.connect("clicked", self.on_copy)
        toolbar.insert(copy_btn, -1)
        
        spacer = Gtk.SeparatorToolItem()
        toolbar.insert(spacer, -1)
        
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Search...")
        self.search_entry.connect("changed", self.on_search)
        
        tool_item = Gtk.ToolItem()
        tool_item.add(self.search_entry)
        toolbar.insert(tool_item, -1)
        
        vbox.pack_start(toolbar, False, False, 0)
        
        # Main content - tree view
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_hexpand(True)
        scrolled.set_vexpand(True)
        
        self.store = Gtk.ListStore(str, str, str, str, str, str)
        self.tree = Gtk.TreeView(model=self.store)
        
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Site", renderer, text=0)
        self.tree.append_column(column)
        
        column = Gtk.TreeViewColumn("Username", renderer, text=1)
        self.tree.append_column(column)
        
        column = Gtk.TreeViewColumn("Category", renderer, text=3)
        self.tree.append_column(column)
        
        self.tree.connect("row-activated", self.on_entry_activated)
        
        scrolled.add(self.tree)
        vbox.pack_start(scrolled, True, True, 0)
        
        # Status bar
        self.statusbar = Gtk.Statusbar()
        vbox.pack_start(self.statusbar, False, False, 0)
        
        self.stack.add_named(vbox, "main")
    
    def run_cli(self, *args, input_text=None):
        cmd = [BIN_PATH] + list(args)
        try:
            result = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=10)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
    
    def on_unlock(self, btn=None):
        pw = self.password_entry.get_text()
        if not pw:
            self.login_status.set_markup('<span foreground="#f38ba8">Please enter password</span>')
            return
        
        self.master_password = pw
        stdout, stderr, rc = self.run_cli("--list", input_text=pw + "\n")
        
        if rc != 0:
            self.login_status.set_markup('<span foreground="#f38ba8">Invalid password</span>')
            self.master_password = None
            return
        
        self.unlocked = True
        self.stack.set_visible_child_name("main")
        self.load_entries()
    
    def on_init(self, btn=None):
        pw = self.password_entry.get_text()
        pw2 = self.password_entry2.get_text()
        
        if not pw or len(pw) < 8:
            self.login_status.set_markup('<span foreground="#f38ba8">Password must be 8+ chars</span>')
            return
        if pw != pw2:
            self.login_status.set_markup('<span foreground="#f38ba8">Passwords do not match</span>')
            return
        
        stdout, stderr, rc = self.run_cli("--init", input_text=pw + "\n")
        
        if rc == 0:
            self.master_password = pw
            self.stack.set_visible_child_name("main")
            self.load_entries()
        else:
            self.login_status.set_markup('<span foreground="#f38ba8">Init failed</span>')
    
    def load_entries(self, search=""):
        self.store.clear()
        
        if not self.master_password:
            return
        
        stdout, stderr, rc = self.run_cli("--list", input_text=self.master_password + "\n")
        
        if rc != 0 or not stdout.strip():
            return
        
        try:
            data = json.loads(stdout.strip())
            self.all_entries = data.get("entries", [])
            
            for e in self.all_entries:
                site = e.get("site", "")
                username = e.get("username", "")
                category = e.get("category", "general")
                password = e.get("password", "")
                url = e.get("url", "")
                
                if search and search.lower() not in site.lower() and search.lower() not in username.lower():
                    continue
                
                self.store.append([site, username, "••••••••", category, url, password])
        except json.JSONDecodeError:
            pass
    
    def on_search(self, entry):
        self.load_entries(entry.get_text())
    
    def on_entry_activated(self, tree, path, col):
        model = tree.get_model()
        row = model[path]
        self.current_entry = {'site': row[0], 'username': row[1], 'password': row[5], 'url': row[4], 'category': row[3]}
        self.show_entry_dialog(edit=True)
    
    def on_add(self, btn=None):
        self.current_entry = None
        self.show_entry_dialog(edit=False)
    
    def on_edit(self, btn=None):
        selection = self.tree.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter:
            row = model[treeiter]
            self.current_entry = {'site': row[0], 'username': row[1], 'password': row[5], 'url': row[4], 'category': row[3]}
            self.show_entry_dialog(edit=True)
    
    def on_delete(self, btn=None):
        selection = self.tree.get_selection()
        model, treeiter = selection.get_selected()
        if not treeiter:
            return
        
        row = model[treeiter]
        site = row[0]
        
        dialog = Gtk.MessageDialog(self.window, 0, Gtk.MessageType.WARNING, Gtk.ButtonsType.OK_CANCEL, f"Delete {site}?")
        if dialog.run() == Gtk.ResponseType.OK:
            self.run_cli("--delete", site, input_text=self.master_password + "\n")
            self.load_entries()
        dialog.destroy()
    
    def on_copy(self, btn=None):
        selection = self.tree.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter:
            password = model[treeiter][5]
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(password, -1)
            self.statusbar.push(0, "Password copied!")
    
    def show_entry_dialog(self, edit=False):
        dialog = Gtk.Dialog(title="Edit Entry" if edit else "Add Entry", parent=self.window, modal=True)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Save", Gtk.ResponseType.OK)
        
        box = dialog.get_content_area()
        box.set_spacing(12)
        box.set_margin_start(20)
        box.set_margin_end(20)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        
        site_entry = Gtk.Entry()
        site_entry.set_placeholder_text("Site (e.g., github.com)")
        user_entry = Gtk.Entry()
        user_entry.set_placeholder_text("Username")
        pass_entry = Gtk.Entry()
        pass_entry.set_placeholder_text("Password")
        pass_entry.set_visibility(False)
        cat_entry = Gtk.Entry()
        cat_entry.set_placeholder_text("Category")
        
        gen_btn = Gtk.Button(label="🎲 Generate")
        def generate(btn):
            stdout, _, _ = self.run_cli("--generate")
            if stdout.strip():
                pass_entry.set_text(stdout.strip())
        gen_btn.connect("clicked", generate)
        
        toggle_btn = Gtk.Button(label="👁")
        def toggle(btn):
            pass_entry.set_visibility(not pass_entry.get_visibility())
        toggle_btn.connect("clicked", toggle)
        
        pass_box = Gtk.Box()
        pass_box.pack_start(pass_entry, True, True, 0)
        pass_box.pack_start(toggle_btn, False, False, 0)
        pass_box.pack_start(gen_btn, False, False, 0)
        
        box.pack_start(Gtk.Label(label="Site:"), False, False, 0)
        box.pack_start(site_entry, False, False, 0)
        box.pack_start(Gtk.Label(label="Username:"), False, False, 0)
        box.pack_start(user_entry, False, False, 0)
        box.pack_start(Gtk.Label(label="Password:"), False, False, 0)
        box.pack_start(pass_box, False, False, 0)
        box.pack_start(Gtk.Label(label="Category:"), False, False, 0)
        box.pack_start(cat_entry, False, False, 0)
        
        if edit and self.current_entry:
            site_entry.set_text(self.current_entry['site'])
            user_entry.set_text(self.current_entry['username'])
            pass_entry.set_text(self.current_entry['password'])
            cat_entry.set_text(self.current_entry.get('category', 'general'))
        
        dialog.show_all()
        
        if dialog.run() == Gtk.ResponseType.OK:
            site = site_entry.get_text()
            user = user_entry.get_text()
            password = pass_entry.get_text()
            category = cat_entry.get_text() or "general"
            
            if site and user and password:
                self.run_cli("--add", site, user, password, input_text=self.master_password + "\n")
                self.load_entries()
        
        dialog.destroy()
    
    def on_export(self, btn=None):
        dialog = Gtk.FileChooserDialog("Export", self.window, Gtk.FileChooserAction.SAVE)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Export", Gtk.ResponseType.OK)
        dialog.set_current_name("passwords.json")
        
        if dialog.run() == Gtk.ResponseType.OK:
            path = dialog.get_filename()
            self.run_cli("--export", path, input_text=self.master_password + "\n")
            self.statusbar.push(0, f"Exported to {path}")
        
        dialog.destroy()
    
    def on_import(self, btn=None):
        dialog = Gtk.FileChooserDialog("Import", self.window, Gtk.FileChooserAction.OPEN)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Import", Gtk.ResponseType.OK)
        
        if dialog.run() == Gtk.ResponseType.OK:
            path = dialog.get_filename()
            self.run_cli("--import", path, input_text=self.master_password + "\n")
            self.load_entries()
            self.statusbar.push(0, "Imported entries")
        
        dialog.destroy()
    
    def on_lock(self, btn=None):
        self.unlocked = False
        self.master_password = None
        self.current_entry = None
        self.store.clear()
        self.password_entry.set_text("")
        self.password_entry2.set_text("")
        self.stack.set_visible_child_name("login")

def main():
    app = PasswordManagerGUI()
    Gtk.main()

if __name__ == "__main__":
    main()
