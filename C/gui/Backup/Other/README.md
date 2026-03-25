# Password Manager GTK3 GUI

Dark-themed modern GUI for the C password manager.

## Requirements

```bash
sudo apt install python3-gi python3-gi-gtk3 gir1.2-gtk-3.0
```

## Run

```bash
cd gui
python3 password_manager_gui.py
```

Or from parent directory:
```bash
cd /home/jay/Documents/Scripts/AI/openclaw/job17/C
python3 gui/password_manager_gui.py
```

## Features

- 🔐 Dark themed modern interface (Catppuccin-inspired)
- 🔍 Search functionality
- 🎲 Password generator
- 📥📤 Import/Export JSON
- 👀 Show/hide passwords
- 📋 Copy to clipboard

## Building

The GUI requires the compiled `password_manager` binary in the parent directory.
