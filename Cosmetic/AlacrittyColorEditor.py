#!/usr/bin/env python3
"""
Alacritty Color Editor - Compact GUI with tabbed interface
Live color editing with automatic backup and real-time updates
"""

import tkinter as tk
from tkinter import ttk, colorchooser, messagebox
import shutil
from pathlib import Path
import re

class AlacrittyColorEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Alacritty Color Editor")
        self.root.geometry("1100x600")

        # Config file path
        self.config_path = Path.home() / ".config" / "alacritty" / "alacritty.toml"
        self.backup_path = Path.home() / ".config" / "alacritty" / "alacritty.toml.backup"

        # Verify config exists
        if not self.config_path.exists():
            messagebox.showerror("Error", f"Config file not found: {self.config_path}")
            root.destroy()
            return

        # Create backup if it doesn't exist
        if not self.backup_path.exists():
            shutil.copy2(self.config_path, self.backup_path)
            print(f"✓ Backup created: {self.backup_path}")

        # Color storage
        self.colors = {}

        # Load current colors
        self.load_colors()

        # Setup UI
        self.setup_ui()

    def load_colors(self):
        """Load colors from alacritty.toml"""
        with open(self.config_path, 'r') as f:
            content = f.read()

        # Parse colors using regex
        color_patterns = {
            'primary.background': r'\[colors\.primary\].*?background\s*=\s*"(#[0-9a-fA-F]{6})"',
            'primary.foreground': r'\[colors\.primary\].*?foreground\s*=\s*"(#[0-9a-fA-F]{6})"',
            'cursor.text': r'\[colors\.cursor\].*?text\s*=\s*"(#[0-9a-fA-F]{6})"',
            'cursor.cursor': r'\[colors\.cursor\].*?cursor\s*=\s*"(#[0-9a-fA-F]{6})"',
            'selection.text': r'\[colors\.selection\].*?text\s*=\s*"(#[0-9a-fA-F]{6})"',
            'selection.background': r'\[colors\.selection\].*?background\s*=\s*"(#[0-9a-fA-F]{6})"',
        }

        # Normal colors
        normal_colors = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']
        for color in normal_colors:
            color_patterns[f'normal.{color}'] = rf'\[colors\.normal\].*?{color}\s*=\s*"(#[0-9a-fA-F]{{6}})"'

        # Bright colors
        for color in normal_colors:
            color_patterns[f'bright.{color}'] = rf'\[colors\.bright\].*?{color}\s*=\s*"(#[0-9a-fA-F]{{6}})"'

        # Extract colors
        for key, pattern in color_patterns.items():
            match = re.search(pattern, content, re.DOTALL)
            if match:
                self.colors[key] = match.group(1)

    def setup_ui(self):
        """Setup compact tabbed interface"""
        # Header frame
        header_frame = ttk.Frame(self.root)
        header_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(header_frame, text="Alacritty Color Editor", 
                 font=("", 14, "bold")).pack(side="left")

        ttk.Label(header_frame, text="Changes apply live!", 
                 foreground="green", font=("", 10)).pack(side="left", padx=20)

        ttk.Button(header_frame, text="🔄 Restore Backup", 
                  command=self.restore_backup).pack(side="right", padx=5)
        ttk.Button(header_frame, text="💾 New Backup", 
                  command=self.create_backup).pack(side="right", padx=5)

        # Tabbed interface
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Primary/Cursor/Selection
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="Primary & UI")

        ui_frame = ttk.Frame(tab1)
        ui_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.create_compact_section(ui_frame, "Primary Colors", 
                                    ['primary.background', 'primary.foreground'])
        self.create_compact_section(ui_frame, "Cursor Colors", 
                                    ['cursor.text', 'cursor.cursor'])
        self.create_compact_section(ui_frame, "Selection Colors", 
                                    ['selection.text', 'selection.background'])

        # Tab 2: Normal Colors
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text="Normal Colors")

        normal_frame = ttk.Frame(tab2)
        normal_frame.pack(fill="both", expand=True, padx=10, pady=10)

        normal_colors = [f'normal.{c}' for c in ['black', 'red', 'green', 'yellow', 
                                                  'blue', 'magenta', 'cyan', 'white']]
        self.create_compact_section(normal_frame, "Normal Colors", normal_colors)

        # Tab 3: Bright Colors
        tab3 = ttk.Frame(notebook)
        notebook.add(tab3, text="Bright Colors")

        bright_frame = ttk.Frame(tab3)
        bright_frame.pack(fill="both", expand=True, padx=10, pady=10)

        bright_colors = [f'bright.{c}' for c in ['black', 'red', 'green', 'yellow', 
                                                  'blue', 'magenta', 'cyan', 'white']]
        self.create_compact_section(bright_frame, "Bright Colors", bright_colors)

    def create_compact_section(self, parent, title, color_keys):
        """Create a compact section with horizontal sliders"""
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.pack(pady=5, fill="both", expand=True)

        # Create grid layout
        for idx, key in enumerate(color_keys):
            if key not in self.colors:
                continue

            row = idx
            self.create_compact_color_control(frame, key, row)

    def create_compact_color_control(self, parent, key, row):
        """Create compact color control with horizontal sliders"""
        # Label
        label_text = key.split('.')[-1].capitalize()
        label = ttk.Label(parent, text=label_text, width=12)
        label.grid(row=row, column=0, padx=5, pady=3, sticky="w")

        # Color preview
        color_value = self.colors[key]
        preview = tk.Canvas(parent, width=60, height=25, bg=color_value, 
                           highlightthickness=2, highlightbackground="gray")
        preview.grid(row=row, column=1, padx=5, pady=3)

        # Hex entry
        hex_var = tk.StringVar(value=color_value)
        hex_entry = ttk.Entry(parent, textvariable=hex_var, width=10)
        hex_entry.grid(row=row, column=2, padx=5, pady=3)

        # Extract RGB values
        rgb = self.hex_to_rgb(color_value)

        # RGB variables
        r_var = tk.IntVar(value=rgb[0])
        g_var = tk.IntVar(value=rgb[1])
        b_var = tk.IntVar(value=rgb[2])

        def update_color_from_sliders(*args):
            r, g, b = r_var.get(), g_var.get(), b_var.get()
            hex_color = f"#{r:02x}{g:02x}{b:02x}"
            preview.configure(bg=hex_color)
            hex_var.set(hex_color)
            self.colors[key] = hex_color
            self.save_colors()

        def update_color_from_hex(*args):
            hex_color = hex_var.get()
            if re.match(r'^#[0-9a-fA-F]{6}$', hex_color):
                rgb = self.hex_to_rgb(hex_color)
                r_var.set(rgb[0])
                g_var.set(rgb[1])
                b_var.set(rgb[2])
                preview.configure(bg=hex_color)
                self.colors[key] = hex_color
                self.save_colors()

        # Color picker button
        def pick_color():
            color = colorchooser.askcolor(self.colors[key], title=f"Choose {label_text}")
            if color[1]:
                hex_var.set(color[1])
                update_color_from_hex()

        pick_btn = ttk.Button(parent, text="🎨", width=3, command=pick_color)
        pick_btn.grid(row=row, column=3, padx=2, pady=3)

        # RGB Sliders frame (horizontal)
        sliders_frame = ttk.Frame(parent)
        sliders_frame.grid(row=row, column=4, columnspan=3, padx=10, pady=3, sticky="ew")

        # Create horizontal RGB sliders
        for i, (color_name, var, fg_color) in enumerate([
            ('R', r_var, '#ff6b6b'), 
            ('G', g_var, '#51cf66'), 
            ('B', b_var, '#4dabf7')
        ]):
            slider_frame = ttk.Frame(sliders_frame)
            slider_frame.pack(side="left", padx=5, fill="x", expand=True)

            top_frame = ttk.Frame(slider_frame)
            top_frame.pack(fill="x")

            ttk.Label(top_frame, text=color_name, width=2, 
                     foreground=fg_color, font=("", 9, "bold")).pack(side="left")

            value_label = ttk.Label(top_frame, text=str(var.get()), width=3, 
                                   font=("", 8))
            value_label.pack(side="right")

            slider = ttk.Scale(slider_frame, from_=0, to=255, 
                             variable=var, orient="horizontal",
                             command=update_color_from_sliders)
            slider.pack(fill="x", expand=True)

            var.trace_add('write', lambda *args, lbl=value_label, v=var: 
                         lbl.config(text=str(v.get())))

        # Bind hex entry
        hex_entry.bind('<Return>', lambda e: update_color_from_hex())
        hex_entry.bind('<FocusOut>', lambda e: update_color_from_hex())

        # Configure column weights for proper expansion
        parent.columnconfigure(4, weight=1)
        parent.columnconfigure(5, weight=1)
        parent.columnconfigure(6, weight=1)

    def hex_to_rgb(self, hex_color):
        """Convert hex color to RGB tuple"""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def save_colors(self):
        """Save colors back to alacritty.toml - updates live!"""
        with open(self.config_path, 'r') as f:
            content = f.read()

        # Replace each color
        for key, color in self.colors.items():
            if '.' in key:
                section, name = key.rsplit('.', 1)
                pattern = rf'(\[colors\.{re.escape(section)}\].*?{re.escape(name)}\s*=\s*)"#[0-9a-fA-F]{{6}}"'
                replacement = rf'\1"{color}"'
                content = re.sub(pattern, replacement, content, flags=re.DOTALL)

        # Write back
        with open(self.config_path, 'w') as f:
            f.write(content)

    def restore_backup(self):
        """Restore from backup"""
        if self.backup_path.exists():
            response = messagebox.askyesno(
                "Restore Backup", 
                "Restore colors from backup?"
            )
            if response:
                shutil.copy2(self.backup_path, self.config_path)
                self.load_colors()
                messagebox.showinfo("Success", "Backup restored! Restart editor to see changes.")
        else:
            messagebox.showerror("Error", "No backup found")

    def create_backup(self):
        """Create a new backup"""
        if self.config_path.exists():
            shutil.copy2(self.config_path, self.backup_path)
            messagebox.showinfo("Success", f"Backup created:\n{self.backup_path}")

def main():
    root = tk.Tk()
    app = AlacrittyColorEditor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
