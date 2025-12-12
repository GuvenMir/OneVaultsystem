[Readme.md](https://github.com/user-attachments/files/24122952/Readme.md)
# 🗄️ VaultSystem – Local Encrypted Text Vault

VaultSystem is a standalone Python application for securely storing and managing text locally.

## Features
- Single-file application (**StartIt.py**)
- CLI, GUI (Tkinter), and built-in web server
- Texts are encrypted with XOR + Base64
- `key.bin` and `kutuphane.json` files are auto-generated
- Add, Search, List, Delete, and Update functionality
- No external dependencies
- Compatible with Windows, Linux, and macOS

## Usage
- Run `python StartIt.py` to open the main menu

### File Structure
- `StartIt.py` (main program)
- `key.bin` (auto-generated encryption key)
- `kutuphane.json` (encrypted text database)

## Security Note
Do **not** include `key.bin` in your repository. Without it, the data cannot be decrypted.

## License
License (see LICENSE file)

## Version 0.0.1 alpha- early edition
