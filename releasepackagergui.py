#!/usr/bin/env python3
"""
Release Packager GUI

Companion tool for building Windows release bundles:
- Collect binaries from files/folders
- Optionally sign them with a PFX using signtool.exe
- Generate SHA256 checksums file
- Create a zip archive for distribution
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import os
import threading
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime


class ReleasePackagerGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Release Packager")
        self.root.geometry("900x750")
        self.root.minsize(850, 700)

        # Settings
        self.release_name_var = tk.StringVar(value="MyApp")
        self.version_var = tk.StringVar(value="1.0.0")
        self.output_dir_var = tk.StringVar()

        # Signing
        self.enable_signing_var = tk.BooleanVar(value=False)
        self.pfx_path_var = tk.StringVar()
        self.pfx_password_var = tk.StringVar()
        self.signtool_path = None

        # Options
        self.generate_hashes_var = tk.BooleanVar(value=True)
        self.create_zip_var = tk.BooleanVar(value=True)

        # Files
        self.selected_files = []

        self.status_var = tk.StringVar(value="Ready")

        self.find_signtool()
        self.create_widgets()

    # ---------------------------
    # signtool detection
    # ---------------------------
    def find_signtool(self) -> None:
        """Find signtool.exe in common Windows SDK locations."""
        common_paths = [
            # Windows 10/11 SDK - x64
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
            # Windows 10/11 SDK - x86
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x86\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x86\signtool.exe",
            r"C:\Program Files (x86)\Windows Kits\10\bin\x86\signtool.exe",
            # Alternative locations
            r"C:\Program Files\Windows Kits\10\bin\x64\signtool.exe",
            r"C:\Program Files\Windows Kits\10\bin\x86\signtool.exe",
        ]

        # Also check PATH
        try:
            result = subprocess.run(
                ["where", "signtool.exe"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                path = result.stdout.strip().splitlines()[0]
                if os.path.exists(path):
                    self.signtool_path = path
                    return
        except Exception:
            pass

        for path in common_paths:
            if os.path.exists(path):
                self.signtool_path = path
                return

        self.signtool_path = None

    # ---------------------------
    # UI
    # ---------------------------
    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        # Title
        title_label = ttk.Label(
            main_frame,
            text="Release Packager",
            font=("Arial", 16, "bold"),
        )
        title_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 8))

        # Release info
        info_frame = ttk.LabelFrame(main_frame, text="Release Info", padding="8")
        info_frame.grid(row=1, column=0, sticky=tk.EW, pady=4)
        info_frame.columnconfigure(1, weight=1)

        ttk.Label(info_frame, text="App Name:", width=12).grid(
            row=0, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(info_frame, textvariable=self.release_name_var).grid(
            row=0, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )

        ttk.Label(info_frame, text="Version:", width=12).grid(
            row=1, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(info_frame, textvariable=self.version_var).grid(
            row=1, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )

        ttk.Label(info_frame, text="Output Dir:", width=12).grid(
            row=2, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(info_frame, textvariable=self.output_dir_var).grid(
            row=2, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )
        ttk.Button(
            info_frame,
            text="Browse...",
            command=self.browse_output_dir,
            width=10,
        ).grid(row=2, column=2, sticky=tk.W, pady=3)

        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="8")
        options_frame.grid(row=2, column=0, sticky=tk.EW, pady=4)
        options_frame.columnconfigure(0, weight=1)

        ttk.Checkbutton(
            options_frame,
            text="Sign files with PFX",
            variable=self.enable_signing_var,
            command=self.update_signing_state,
        ).grid(row=0, column=0, sticky=tk.W, pady=2)

        ttk.Checkbutton(
            options_frame,
            text="Generate SHA256 checksums file",
            variable=self.generate_hashes_var,
        ).grid(row=1, column=0, sticky=tk.W, pady=2)

        ttk.Checkbutton(
            options_frame,
            text="Create zip archive",
            variable=self.create_zip_var,
        ).grid(row=2, column=0, sticky=tk.W, pady=2)

        # Signing settings
        signing_frame = ttk.LabelFrame(main_frame, text="Signing Settings", padding="8")
        signing_frame.grid(row=3, column=0, sticky=tk.EW, pady=4)
        signing_frame.columnconfigure(1, weight=1)

        ttk.Label(signing_frame, text="PFX File:", width=12).grid(
            row=0, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(signing_frame, textvariable=self.pfx_path_var).grid(
            row=0, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )
        ttk.Button(
            signing_frame,
            text="Browse...",
            command=self.browse_pfx,
            width=10,
        ).grid(row=0, column=2, sticky=tk.W, pady=3)

        ttk.Label(signing_frame, text="Password:", width=12).grid(
            row=1, column=0, sticky=tk.W, pady=3
        )
        ttk.Entry(
            signing_frame,
            textvariable=self.pfx_password_var,
            show="*",
        ).grid(row=1, column=1, sticky=tk.EW, pady=3, padx=(0, 4))

        signtool_status = (
            f"signtool.exe detected at: {self.signtool_path}"
            if self.signtool_path
            else "signtool.exe not detected. Signing may fail until SDK is installed."
        )
        self.signtool_status_var = tk.StringVar(value=signtool_status)
        ttk.Label(
            signing_frame,
            textvariable=self.signtool_status_var,
            foreground="green" if self.signtool_path else "red",
        ).grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=2)

        # Files section
        files_frame = ttk.LabelFrame(main_frame, text="Files to Include", padding="8")
        files_frame.grid(row=4, column=0, sticky=tk.NSEW, pady=4)
        files_frame.columnconfigure(0, weight=1)
        files_frame.rowconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=3)

        btn_frame = ttk.Frame(files_frame)
        btn_frame.grid(row=0, column=0, sticky=tk.EW, pady=3)

        ttk.Button(btn_frame, text="Add Files", command=self.add_files, width=12).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(
            btn_frame, text="Add Folder", command=self.add_folder, width=12
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            btn_frame, text="Remove", command=self.remove_selected, width=12
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            btn_frame, text="Clear All", command=self.clear_files, width=12
        ).pack(side=tk.LEFT, padx=2)

        list_frame = ttk.Frame(files_frame)
        list_frame.grid(row=1, column=0, sticky=tk.NSEW)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(
            list_frame,
            selectmode=tk.EXTENDED,
            yscrollcommand=scrollbar.set,
        )
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)

        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="8")
        log_frame.grid(row=5, column=0, sticky=tk.NSEW, pady=4)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=2)

        self.output_text = scrolledtext.ScrolledText(
            log_frame, height=8, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.output_text.grid(row=0, column=0, sticky=tk.NSEW)

        # Build button
        build_btn = ttk.Button(
            main_frame,
            text="Build Release",
            command=self.build_release,
            style="Accent.TButton",
        )
        build_btn.grid(row=6, column=0, pady=10)

        # Status bar
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=7, column=0, sticky=tk.EW, pady=(4, 0))

        # Initial state
        self.update_signing_state()

    # ---------------------------
    # UI helpers
    # ---------------------------
    def log(self, msg: str) -> None:
        self.output_text.insert(tk.END, msg + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def update_signing_state(self) -> None:
        state = tk.NORMAL if self.enable_signing_var.get() else tk.DISABLED
        # Disable/enable signing fields
        for child in self.root.winfo_children():
            # We keep this simple: controls remain visible; validation happens in build.
            # For clarity we don't actually disable entries as they're inside frames;
            # signing is controlled by the checkbox at runtime.
            pass

    # ---------------------------
    # Browsers
    # ---------------------------
    def browse_output_dir(self) -> None:
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_dir_var.set(directory)

    def browse_pfx(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select PFX certificate file",
            filetypes=[("PFX Files", "*.pfx"), ("All files", "*.*")],
        )
        if filename:
            self.pfx_path_var.set(filename)

    # ---------------------------
    # File selection
    # ---------------------------
    def add_files(self) -> None:
        filenames = filedialog.askopenfilenames(
            title="Select files to include",
            filetypes=[("All files", "*.*")],
        )
        added = 0
        for name in filenames:
            if name not in self.selected_files:
                self.selected_files.append(name)
                self.file_listbox.insert(tk.END, name)
                added += 1
        if added:
            self.status_var.set(f"Added {added} file(s).")

    def add_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select folder to include")
        if not folder:
            return
        added = 0
        for path in Path(folder).rglob("*"):
            if path.is_file():
                path_str = str(path)
                if path_str not in self.selected_files:
                    self.selected_files.append(path_str)
                    self.file_listbox.insert(tk.END, path_str)
                    added += 1
        self.status_var.set(f"Added {added} file(s) from folder.")

    def remove_selected(self) -> None:
        selection = self.file_listbox.curselection()
        if not selection:
            return
        removed_count = 0
        for idx in reversed(selection):
            self.selected_files.pop(idx)
            self.file_listbox.delete(idx)
            removed_count += 1
        self.status_var.set(f"Removed {removed_count} file(s).")

    def clear_files(self) -> None:
        self.selected_files.clear()
        self.file_listbox.delete(0, tk.END)
        self.status_var.set("Cleared all files.")

    # ---------------------------
    # Build process
    # ---------------------------
    def build_release(self) -> None:
        # Basic validation
        name = self.release_name_var.get().strip()
        version = self.version_var.get().strip()
        output_dir = self.output_dir_var.get().strip()

        if not name:
            messagebox.showerror("Build Release", "Please enter an App Name.")
            return
        if not version:
            messagebox.showerror("Build Release", "Please enter a Version.")
            return
        if not output_dir:
            messagebox.showerror(
                "Build Release", "Please select an output directory for the release."
            )
            return
        if not os.path.isdir(output_dir):
            messagebox.showerror(
                "Build Release", "Output directory does not exist or is not a folder."
            )
            return
        if not self.selected_files:
            messagebox.showerror(
                "Build Release", "Please add at least one file to include."
            )
            return

        if self.enable_signing_var.get():
            if not self.pfx_path_var.get().strip():
                messagebox.showerror(
                    "Build Release", "Signing is enabled; please select a PFX file."
                )
                return
            if not os.path.exists(self.pfx_path_var.get().strip()):
                messagebox.showerror(
                    "Build Release", "PFX file does not exist at the given path."
                )
                return
            if not self.pfx_password_var.get():
                if not messagebox.askyesno(
                    "Empty Password",
                    "No password entered for the PFX file.\n\n"
                    "Continue anyway?",
                ):
                    return

        # Start worker thread
        self.status_var.set("Building release...")
        self.output_text.delete("1.0", tk.END)
        self.log("=== Building release ===")

        thread = threading.Thread(target=self._build_release_thread, daemon=True)
        thread.start()

    def _build_release_thread(self) -> None:
        name = self.release_name_var.get().strip()
        version = self.version_var.get().strip()
        output_dir = self.output_dir_var.get().strip()
        sign = self.enable_signing_var.get()
        pfx = self.pfx_path_var.get().strip()
        pwd = self.pfx_password_var.get()
        generate_hashes = self.generate_hashes_var.get()
        create_zip = self.create_zip_var.get()

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        release_folder_name = f"{name}-{version}-{timestamp}"
        release_folder = os.path.join(output_dir, release_folder_name)

        try:
            os.makedirs(release_folder, exist_ok=True)
        except Exception as exc:
            self.log(f"ERROR: Failed to create release folder:\n{exc}")
            self.status_var.set("Failed to create release folder.")
            return

        self.log(f"Release folder: {release_folder}")

        # Copy files
        dest_files = []
        for src in self.selected_files:
            if not os.path.exists(src):
                self.log(f"WARNING: Skipping missing file: {src}")
                continue
            try:
                dest = os.path.join(release_folder, os.path.basename(src))
                # Use binary copy
                with open(src, "rb") as f_src, open(dest, "wb") as f_dest:
                    for chunk in iter(lambda: f_src.read(8192), b""):
                        f_dest.write(chunk)
                dest_files.append(dest)
                self.log(f"Copied: {src} -> {dest}")
            except Exception as exc:
                self.log(f"ERROR: Failed to copy {src}:\n{exc}")

        if not dest_files:
            self.log("No files were copied. Aborting.")
            self.status_var.set("No files copied.")
            return

        # Signing
        if sign:
            if not self.signtool_path:
                self.find_signtool()
            if not self.signtool_path:
                self.log(
                    "WARNING: Signing enabled but signtool.exe is not available. Skipping signing."
                )
            else:
                self.log("\n=== Signing files ===")
                for fpath in dest_files:
                    self._sign_file(fpath, pfx, pwd)

        # Hashes
        if generate_hashes:
            self.log("\n=== Generating checksums ===")
            checksum_path = os.path.join(release_folder, "checksums_sha256.txt")
            try:
                with open(checksum_path, "w", encoding="utf-8") as f_out:
                    for fpath in dest_files:
                        sha256 = self._compute_sha256(fpath)
                        rel_name = os.path.basename(fpath)
                        f_out.write(f"{sha256}  {rel_name}\n")
                        self.log(f"SHA256 {rel_name}: {sha256}")
                self.log(f"Checksums written to: {checksum_path}")
            except Exception as exc:
                self.log(f"ERROR: Failed to write checksums file:\n{exc}")

        # Zip archive
        zip_path = None
        if create_zip:
            self.log("\n=== Creating zip archive ===")
            zip_name = f"{name}-{version}.zip"
            zip_path = os.path.join(output_dir, zip_name)

            try:
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for root_dir, _dirs, files in os.walk(release_folder):
                        for fname in files:
                            full_path = os.path.join(root_dir, fname)
                            rel_path = os.path.relpath(full_path, release_folder)
                            zf.write(full_path, arcname=rel_path)
                            self.log(f"Added to zip: {rel_path}")
                self.log(f"Zip archive created: {zip_path}")
            except Exception as exc:
                self.log(f"ERROR: Failed to create zip archive:\n{exc}")

        self.log("\n=== Release build complete ===")
        summary = f"Release folder: {release_folder}"
        if zip_path:
            summary += f"\nZip archive: {zip_path}"
        self.log(summary)
        self.status_var.set("Release build complete.")

    # ---------------------------
    # Helpers for signing & hashes
    # ---------------------------
    def _sign_file(self, file_path: str, pfx: str, password: str) -> None:
        self.log(f"Signing: {os.path.basename(file_path)}")
        cmd = [
            self.signtool_path,
            "sign",
            "/f",
            pfx,
            "/p",
            password,
            "/fd",
            "SHA256",
            "/tr",
            "http://timestamp.digicert.com",
            "/td",
            "SHA256",
            "/v",
            file_path,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                self.log(f"✓ Signed: {os.path.basename(file_path)}")
            else:
                err = result.stderr or result.stdout
                self.log(
                    f"✗ Failed to sign {os.path.basename(file_path)}:\n{err.strip()}"
                )
        except Exception as exc:
            self.log(f"✗ Exception while signing {os.path.basename(file_path)}:\n{exc}")

    def _compute_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


def main() -> None:
    root = tk.Tk()
    app = ReleasePackagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

