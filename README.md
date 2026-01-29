# Release Packager GUI

Companion tool to the Code Signing Tool GUI for building distributable Windows releases.

## Features

- **Release metadata**
  - App name and version
  - Timestamped release folder
- **File collection**
  - Add individual files
  - Add entire folders (recursively)
- **Optional code signing**
  - Sign all copied files with a PFX using `signtool.exe`
  - Uses SHA256 and RFC 3161 timestamp
- **Checksums**
  - Generate `checksums_sha256.txt` in the release folder
- **Zip packaging**
  - Create a `.zip` archive for the release folder

## Requirements

- Windows 10/11
- Python 3.6+ (tkinter included)
- Optional: Windows SDK (`signtool.exe`) for signing

## Running

From this folder:

```bash
python releasepackagergui.py
```

Or on Windows, double-click `run_releasepackager.bat`.

## Notes

- If signing is enabled but `signtool.exe` is not available, the tool will skip signing and log a warning.
- Large files are copied and hashed in streaming mode to avoid high memory usage.

