#!/usr/bin/env python3
"""
Alacritty Color Editor & Theming Tool
"""

import tkinter as tk
from tkinter import ttk, colorchooser, messagebox, filedialog
import shutil
from pathlib import Path
import re
import json
from datetime import datetime
from PIL import Image
import colorsys

class ColorTheory:
    """Color theory utilities for generating variations"""

    @staticmethod
    def hex_to_rgb(hex_color):
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    @staticmethod
    def rgb_to_hex(r, g, b):
        return f"#{r:02x}{g:02x}{b:02x}"

    @staticmethod
    def rgb_to_hsv(r, g, b):
        return colorsys.rgb_to_hsv(r/255, g/255, b/255)

    @staticmethod
    def hsv_to_rgb(h, s, v):
        r, g, b = colorsys.hsv_to_rgb(h, s, v)
        return (int(r*255), int(g*255), int(b*255))

    @staticmethod
    def shade(hex_color, factor):
        """Generate shade"""
        r, g, b = ColorTheory.hex_to_rgb(hex_color)
        r = int(max(0, min(255, r * factor)))
        g = int(max(0, min(255, g * factor)))
        b = int(max(0, min(255, b * factor)))
        return ColorTheory.rgb_to_hex(r, g, b)

    @staticmethod
    def adjust_saturation(hex_color, saturation_factor):
        """Adjust saturation"""
        r, g, b = ColorTheory.hex_to_rgb(hex_color)
        h, s, v = ColorTheory.rgb_to_hsv(r, g, b)
        s = max(0, min(1, s * saturation_factor))
        r, g, b = ColorTheory.hsv_to_rgb(h, s, v)
        return ColorTheory.rgb_to_hex(r, g, b)

    @staticmethod
    def adjust_hue(hex_color, hue_shift):
        """Shift hue"""
        r, g, b = ColorTheory.hex_to_rgb(hex_color)
        h, s, v = ColorTheory.rgb_to_hsv(r, g, b)
        h = (h + hue_shift) % 1.0
        r, g, b = ColorTheory.hsv_to_rgb(h, s, v)
        return ColorTheory.rgb_to_hex(r, g, b)

class ImagePaletteExtractor:
    """Extract dominant colors from images"""

    @staticmethod
    def get_palette(image_path, num_colors=12):
        """Extract 12 dominant colors"""
        img = Image.open(image_path).convert('RGB')
        img.thumbnail((200, 200))
        pixels = list(img.getdata())

        from collections import Counter
        color_counts = Counter(pixels)
        sorted_colors = sorted(color_counts.items(), key=lambda x: x[1], reverse=True)

        palette = []
        for color, count in sorted_colors[:num_colors*4]:
            if len(palette) >= num_colors:
                break

            r, g, b = color
            is_similar = False
            for pr, pg, pb in palette:
                dist = abs(r-pr) + abs(g-pg) + abs(b-pb)
                if dist < 30:
                    is_similar = True
                    break

            if not is_similar:
                palette.append(color)

        while len(palette) < num_colors:
            if palette:
                r, g, b = palette[0]
                h, s, v = colorsys.rgb_to_hsv(r/255, g/255, b/255)
                h = (h + (len(palette) * 0.08)) % 1.0
                nr, ng, nb = colorsys.hsv_to_rgb(h, s, v)
                palette.append((int(nr*255), int(ng*255), int(nb*255)))

        return [f"#{r:02x}{g:02x}{b:02x}" for r, g, b in palette[:num_colors]]

class RofiConfigSyncer:
    """Intelligently sync colors to rofi config"""

    @staticmethod
    def sync_to_rofi(colors_dict, rofi_path):
        """Append color overrides at the end of rofi config"""
        with open(rofi_path, 'r') as f:
            content = f.read()

        # Remove any existing Alacritty sync block
        content = re.sub(
            r'/\* Alacritty Color Sync.*?\*/\s*\* \{[^}]*\}',
            '',
            content,
            flags=re.DOTALL
        )

        # Map alacritty colors to rofi variable names
        color_mapping = {
            'bg0': 'primary.background',
            'bg1': 'primary.background',
            'bg2': 'primary.background',
            'bg3': 'cursor.cursor',
            'fg0': 'primary.foreground',
            'fg1': 'primary.foreground',
            'fg2': 'selection.text',
            'red': 'normal.red',
            'green': 'normal.green',
            'yellow': 'normal.yellow',
            'blue': 'normal.blue',
            'magenta': 'normal.magenta',
            'cyan': 'normal.cyan',
        }

        # Build color override block
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        override_block = f"\n\n/* Alacritty Color Sync - {timestamp} */\n* {{\n"

        for rofi_var, alacritty_key in color_mapping.items():
            if alacritty_key in colors_dict:
                color_value = colors_dict[alacritty_key]
                override_block += f"  {rofi_var}: {color_value};\n"

        override_block += "}\n"

        # Append to end of config
        content = content.rstrip() + override_block

        with open(rofi_path, 'w') as f:
            f.write(content)

class AlacrittyColorEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Alacritty Color Editor & Ricing Tool - Vibecoded Tool 'Cause I'm lazy")
        self.root.geometry("1400x850")

        self.config_path = Path.home() / ".config" / "alacritty" / "alacritty.toml"
        self.backup_path = Path.home() / ".config" / "alacritty" / "alacritty.toml.backup"
        self.history_path = Path.home() / ".config" / "alacritty" / "color_history.json"

        if not self.config_path.exists():
            messagebox.showerror("Error", f"Config not found: {self.config_path}")
            root.destroy()
            return

        if not self.backup_path.exists():
            shutil.copy2(self.config_path, self.backup_path)

        self.colors = {}
        self.history = []
        self.load_colors()
        self.load_history()

        self.setup_ui()

    def load_colors(self):
        """Load colors from alacritty.toml"""
        with open(self.config_path, 'r') as f:
            content = f.read()

        color_patterns = {
            'primary.background': r'\[colors\.primary\].*?background\s*=\s*"(#[0-9a-fA-F]{6})"',
            'primary.foreground': r'\[colors\.primary\].*?foreground\s*=\s*"(#[0-9a-fA-F]{6})"',
            'cursor.text': r'\[colors\.cursor\].*?text\s*=\s*"(#[0-9a-fA-F]{6})"',
            'cursor.cursor': r'\[colors\.cursor\].*?cursor\s*=\s*"(#[0-9a-fA-F]{6})"',
            'selection.text': r'\[colors\.selection\].*?text\s*=\s*"(#[0-9a-fA-F]{6})"',
            'selection.background': r'\[colors\.selection\].*?background\s*=\s*"(#[0-9a-fA-F]{6})"',
        }

        normal_colors = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']
        for color in normal_colors:
            color_patterns[f'normal.{color}'] = rf'\[colors\.normal\].*?{color}\s*=\s*"(#[0-9a-fA-F]{{6}})"'
            color_patterns[f'bright.{color}'] = rf'\[colors\.bright\].*?{color}\s*=\s*"(#[0-9a-fA-F]{{6}})"'

        for key, pattern in color_patterns.items():
            match = re.search(pattern, content, re.DOTALL)
            if match:
                self.colors[key] = match.group(1)

    def load_history(self):
        if self.history_path.exists():
            with open(self.history_path, 'r') as f:
                self.history = json.load(f)

    def save_history(self):
        with open(self.history_path, 'w') as f:
            json.dump(self.history, f, indent=2)

    def add_to_history(self, name, colors_dict):
        entry = {
            'name': name,
            'timestamp': datetime.now().isoformat(),
            'colors': colors_dict
        }
        self.history.insert(0, entry)
        self.history = self.history[:50]
        self.save_history()

    def setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)

        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="Color Editor")
        self.setup_editor_tab(tab1)

        tab3 = ttk.Frame(notebook)
        notebook.add(tab3, text="Color Tools")
        self.setup_tools_tab(tab3)

        tab4 = ttk.Frame(notebook)
        notebook.add(tab4, text="Sync Configs")
        self.setup_sync_tab(tab4)

        tab5 = ttk.Frame(notebook)
        notebook.add(tab5, text="History")
        self.setup_history_tab(tab5)

    def setup_editor_tab(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        header = ttk.Frame(tab)
        header.grid(row=0, column=0, pady=10, padx=10, sticky="ew")

        ttk.Label(header, text="Alacritty Color Editor", font=("", 12, "bold")).pack(side="left")
        ttk.Button(header, text="🔄 Restore", command=self.restore_backup).pack(side="right", padx=5)
        ttk.Button(header, text="💾 Backup", command=self.create_backup).pack(side="right", padx=5)

        canvas_frame = ttk.Frame(tab)
        canvas_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)

        canvas = tk.Canvas(canvas_frame)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        # Bind to canvas resize to make scrollable_frame fill width
        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind('<Configure>', on_canvas_configure)

        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        sections = [
            ('Primary & UI', ['primary.background', 'primary.foreground', 'cursor.text', 'cursor.cursor', 'selection.text', 'selection.background']),
            ('Normal Colors', [f'normal.{c}' for c in ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']]),
            ('Bright Colors', [f'bright.{c}' for c in ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']])
        ]

        for section_name, color_keys in sections:
            self.create_section(scrollable_frame, section_name, color_keys)


    def generate_palette_previews(self, base_palette):
        """Generate 20 color scheme variations"""
        self.palette_canvas.delete("all")
        self.palette_schemes = []

        schemes = []

        schemes.append(("1. Original", base_palette))

        for i in range(1, 5):
            factor = 1.0 + (i * 0.15)
            scheme = [ColorTheory.shade(c, factor) for c in base_palette]
            schemes.append((f"{i+1}. Light +{i*15}%", scheme))

        for i in range(1, 5):
            factor = 1.0 - (i * 0.15)
            scheme = [ColorTheory.shade(c, factor) for c in base_palette]
            schemes.append((f"{i+5}. Dark -{i*15}%", scheme))

        for i in range(1, 5):
            sat_factor = 0.6 + (i * 0.1)
            scheme = [ColorTheory.adjust_saturation(c, sat_factor) for c in base_palette]
            schemes.append((f"{i+9}. Saturated +{int((sat_factor-0.6)*100)}%", scheme))

        for i in range(1, 5):
            hue_shift = i * 0.08
            scheme = [ColorTheory.adjust_hue(c, hue_shift) for c in base_palette]
            schemes.append((f"{i+13}. Hue +{int(hue_shift*360)}°", scheme))

        scheme = [ColorTheory.shade(ColorTheory.adjust_saturation(c, 1.3), 1.15) for c in base_palette]
        schemes.append(("18. Warm & Bright", scheme))

        scheme = [ColorTheory.shade(ColorTheory.adjust_saturation(c, 0.8), 0.85) for c in base_palette]
        schemes.append(("19. Cool & Muted", scheme))

        scheme = [ColorTheory.adjust_hue(ColorTheory.shade(c, 1.1), 0.15) for c in base_palette]
        schemes.append(("20. Sunset Shift", scheme))

        y = 10
        for scheme_idx, (scheme_name, scheme) in enumerate(schemes):
            self.draw_palette_preview(scheme_name, scheme, y, scheme_idx)
            self.palette_schemes.append(scheme)
            y += 80

        self.palette_canvas.config(scrollregion=self.palette_canvas.bbox("all"))

    def draw_palette_preview(self, name, palette, y, scheme_idx):
        """Draw a 12-color palette preview"""
        x = 20

        self.palette_canvas.create_text(x, y, text=name, anchor="nw", font=("", 10, "bold"))

        for row in range(2):
            for col in range(6):
                idx = row * 6 + col
                if idx < len(palette):
                    color = palette[idx]
                    rect_x = x + col * 65
                    rect_y = y + 20 + row * 35

                    tag = f"scheme_{scheme_idx}"
                    rect = self.palette_canvas.create_rectangle(
                        rect_x, rect_y, rect_x + 60, rect_y + 30,
                        fill=color, outline="black", width=2, tags=tag
                    )

                    self.palette_canvas.create_text(
                        rect_x + 30, rect_y + 45, text=color, anchor="n", 
                        font=("", 7), tags=tag
                    )

        self.palette_canvas.tag_bind(f"scheme_{scheme_idx}", "<Button-1>", 
                                     lambda e, idx=scheme_idx: self.apply_palette(idx))

    def on_palette_click(self, event):
        tags = self.palette_canvas.gettags("current")
        for tag in tags:
            if tag.startswith("scheme_"):
                scheme_idx = int(tag.split("_")[1])
                self.apply_palette(scheme_idx)
                break

    def apply_palette(self, scheme_idx):
        """Apply selected palette"""
        if scheme_idx >= len(self.palette_schemes):
            return

        palette = self.palette_schemes[scheme_idx]

        normal_names = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']

        for i, name in enumerate(normal_names):
            if i < len(palette):
                self.colors[f'normal.{name}'] = palette[i]

        for i, name in enumerate(normal_names):
            if (i + 8) < len(palette):
                self.colors[f'bright.{name}'] = palette[i + 8]
            else:
                self.colors[f'bright.{name}'] = ColorTheory.shade(palette[i], 1.3)

        self.save_colors()
        messagebox.showinfo("Success", "Palette applied to Alacritty!")
        self.add_to_history("Auto-applied scheme", self.colors.copy())

    def setup_tools_tab(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        frame = ttk.Frame(tab)
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        ttk.Label(frame, text="Color Theory Tools", font=("", 12, "bold")).pack(pady=10)

        input_frame = ttk.Frame(tab)
        input_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        input_frame.grid_rowconfigure(1, weight=1)
        input_frame.grid_columnconfigure(0, weight=1)

        inner_frame = ttk.Frame(input_frame)
        inner_frame.grid(row=0, column=0, pady=10, sticky="ew")

        ttk.Label(inner_frame, text="Select Color:").pack(side="left", padx=5)

        self.color_var = tk.StringVar(value='primary.background')
        color_combo = ttk.Combobox(inner_frame, textvariable=self.color_var, width=20, state="readonly")
        color_combo['values'] = list(self.colors.keys())
        color_combo.pack(side="left", padx=5)

        ttk.Button(inner_frame, text="Generate Variations", command=self.show_color_variations).pack(side="left", padx=5)

        self.tools_frame = ttk.LabelFrame(input_frame, text="Variations", padding=10)
        self.tools_frame.grid(row=1, column=0, sticky="nsew", pady=10)
        self.tools_frame.grid_rowconfigure(0, weight=1)
        self.tools_frame.grid_columnconfigure(0, weight=1)

        self.tools_canvas = tk.Canvas(self.tools_frame, bg="white")
        self.tools_canvas.pack(fill="both", expand=True)

    def show_color_variations(self):
        color_key = self.color_var.get()
        if not color_key or color_key not in self.colors:
            return

        color = self.colors[color_key]
        self.tools_canvas.delete("all")
        y = 10

        self.tools_canvas.create_text(10, y, text=f"Original: {color}", anchor="nw", font=("", 10, "bold"))
        self.tools_canvas.create_rectangle(10, y+20, 60, y+50, fill=color, outline="black")
        y += 70

        comp = ColorTheory.shade(color, 0.5)
        self.tools_canvas.create_text(10, y, text=f"Darkened: {comp}", anchor="nw", font=("", 10, "bold"))
        self.tools_canvas.create_rectangle(10, y+20, 60, y+50, fill=comp, outline="black")
        y += 70

        light = ColorTheory.shade(color, 1.5)
        self.tools_canvas.create_text(10, y, text=f"Lightened: {light}", anchor="nw", font=("", 10, "bold"))
        self.tools_canvas.create_rectangle(10, y+20, 60, y+50, fill=light, outline="black")
        y += 70

        self.tools_canvas.create_text(10, y, text="Shades & Tints:", anchor="nw", font=("", 10, "bold"))
        y += 30

        for factor, label in [(0.4, "Very Dark"), (0.6, "Dark"), (0.8, "Medium"), (1.0, "Original"), (1.2, "Light"), (1.4, "Very Light")]:
            shade = ColorTheory.shade(color, factor)
            self.tools_canvas.create_rectangle(10, y, 200, y+25, fill=shade, outline="black")
            self.tools_canvas.create_text(210, y+12, text=f"{label}: {shade}", anchor="w", font=("", 9))
            y += 30

    def setup_sync_tab(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        frame = ttk.Frame(tab)
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        ttk.Label(frame, text="Sync Colors to Other Configs", font=("", 12, "bold")).pack(pady=10)

        content_frame = ttk.Frame(tab)
        content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        content_frame.grid_rowconfigure(0, weight=1)

        rofi_path = Path.home() / ".config" / "rofi" / "config.rasi"

        info_frame = ttk.LabelFrame(content_frame, text="Available Configs", padding=10)
        info_frame.pack(fill="both", expand=True)

        if rofi_path.exists():
            btn_frame = ttk.Frame(info_frame)
            btn_frame.pack(fill="x", pady=10)

            ttk.Label(btn_frame, text="📄 rofi config", width=20, font=("", 10)).pack(side="left")
            ttk.Label(btn_frame, text=str(rofi_path), foreground="gray").pack(side="left", padx=20)
            ttk.Button(btn_frame, text="Sync Colors →", 
                      command=lambda: self.sync_rofi_safely(rofi_path)).pack(side="right", padx=5)
        else:
            ttk.Label(info_frame, text="No rofi config found at ~/.config/rofi/config.rasi", 
                     foreground="orange").pack(pady=20)

    def sync_rofi_safely(self, rofi_path):
        """Safely sync to rofi config"""
        try:
            backup_path = str(rofi_path) + ".backup"
            shutil.copy2(rofi_path, backup_path)

            RofiConfigSyncer.sync_to_rofi(self.colors, rofi_path)
            messagebox.showinfo("Success", f"Rofi config synced!\nColors appended at bottom.\nBackup: {backup_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sync rofi: {e}")

    def setup_history_tab(self, tab):
        tab.grid_rowconfigure(0, weight=1)
        tab.grid_columnconfigure(0, weight=1)

        frame = ttk.Frame(tab)
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        list_frame = ttk.LabelFrame(frame, text="Saved Schemes", padding=10)
        list_frame.grid(row=0, column=0, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.history_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.history_listbox.pack(fill="both", expand=True, side="left")
        scrollbar.config(command=self.history_listbox.yview)

        for entry in self.history:
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime("%Y-%m-%d %H:%M")
            self.history_listbox.insert(tk.END, f"{entry['name']} ({timestamp})")

        btn_frame = ttk.Frame(tab)
        btn_frame.grid(row=1, column=0, sticky="ew", pady=10)

        ttk.Button(btn_frame, text="📋 Load Selected", command=self.load_from_history).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑️ Delete Selected", command=self.delete_from_history).pack(side="left", padx=5)

    def load_from_history(self):
        selection = self.history_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Select a scheme first")
            return

        idx = selection[0]
        entry = self.history[idx]
        self.colors = entry['colors'].copy()
        self.save_colors()
        messagebox.showinfo("Success", "Colors loaded from history!")

    def delete_from_history(self):
        selection = self.history_listbox.curselection()
        if not selection:
            return

        idx = selection[0]
        self.history.pop(idx)
        self.save_history()
        self.history_listbox.delete(idx)

    def create_section(self, parent, title, color_keys):
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.pack(pady=5, padx=10, fill="x", expand=False)

        for row, key in enumerate(color_keys):
            if key not in self.colors:
                continue
            self.create_color_control(frame, key, row)

    def create_color_control(self, parent, key, row):
        label_text = key.split('.')[-1].capitalize()
        label = ttk.Label(parent, text=label_text, width=12)
        label.grid(row=row, column=0, padx=5, pady=3, sticky="w")

        color_value = self.colors[key]
        preview = tk.Canvas(parent, width=60, height=25, bg=color_value, 
                           highlightthickness=2, highlightbackground="gray")
        preview.grid(row=row, column=1, padx=5, pady=3)

        hex_var = tk.StringVar(value=color_value)
        hex_entry = ttk.Entry(parent, textvariable=hex_var, width=10)
        hex_entry.grid(row=row, column=2, padx=5, pady=3)

        r, g, b = ColorTheory.hex_to_rgb(color_value)
        r_var, g_var, b_var = tk.IntVar(value=r), tk.IntVar(value=g), tk.IntVar(value=b)

        def update_from_sliders(*args):
            hex_color = f"#{r_var.get():02x}{g_var.get():02x}{b_var.get():02x}"
            preview.configure(bg=hex_color)
            hex_var.set(hex_color)
            self.colors[key] = hex_color
            self.save_colors()

        def update_from_hex(*args):
            hex_color = hex_var.get()
            if re.match(r'^#[0-9a-fA-F]{6}$', hex_color):
                r, g, b = ColorTheory.hex_to_rgb(hex_color)
                r_var.set(r)
                g_var.set(g)
                b_var.set(b)
                preview.configure(bg=hex_color)
                self.colors[key] = hex_color
                self.save_colors()

        def pick_color():
            color = colorchooser.askcolor(self.colors[key])
            if color[1]:
                hex_var.set(color[1])
                update_from_hex()

        ttk.Button(parent, text="🎨", width=3, command=pick_color).grid(row=row, column=3, padx=2, pady=3)

        sliders_frame = ttk.Frame(parent)
        sliders_frame.grid(row=row, column=4, columnspan=3, padx=10, pady=3, sticky="ew")

        for color_name, var, fg_color in [('R', r_var, '#ff6b6b'), ('G', g_var, '#51cf66'), ('B', b_var, '#4dabf7')]:
            slider_frame = ttk.Frame(sliders_frame)
            slider_frame.pack(side="left", padx=5, fill="both", expand=True)

            top_frame = ttk.Frame(slider_frame)
            top_frame.pack(fill="x")

            ttk.Label(top_frame, text=color_name, foreground=fg_color, font=("", 9, "bold")).pack(side="left")
            value_label = ttk.Label(top_frame, text=str(var.get()), font=("", 8))
            value_label.pack(side="right")

            slider = ttk.Scale(slider_frame, from_=0, to=255, variable=var, 
                             orient="horizontal", command=update_from_sliders)
            slider.pack(fill="both", expand=True)

            var.trace_add('write', lambda *args, lbl=value_label, v=var: lbl.config(text=str(v.get())))

        hex_entry.bind('<Return>', lambda e: update_from_hex())
        hex_entry.bind('<FocusOut>', lambda e: update_from_hex())

        parent.columnconfigure(4, weight=1)
        parent.columnconfigure(5, weight=1)
        parent.columnconfigure(6, weight=1)

    def save_colors(self):
        with open(self.config_path, 'r') as f:
            content = f.read()

        for key, color in self.colors.items():
            if '.' in key:
                section, name = key.rsplit('.', 1)
                pattern = rf'(\[colors\.{re.escape(section)}\].*?{re.escape(name)}\s*=\s*)"#[0-9a-fA-F]{{6}}"'
                replacement = rf'\1"{color}"'
                content = re.sub(pattern, replacement, content, flags=re.DOTALL)

        with open(self.config_path, 'w') as f:
            f.write(content)

    def restore_backup(self):
        if self.backup_path.exists():
            response = messagebox.askyesno("Restore", "Restore from backup?")
            if response:
                shutil.copy2(self.backup_path, self.config_path)
                self.load_colors()
                messagebox.showinfo("Success", "Restored!")

    def create_backup(self):
        if self.config_path.exists():
            shutil.copy2(self.config_path, self.backup_path)
            messagebox.showinfo("Success", "Backup created!")

def main():
    root = tk.Tk()
    app = AlacrittyColorEditor(root)
    root.mainloop()

if __name__ == "__main__":
    main()
