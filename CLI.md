# CLI Usage

**Commands:** `encrypt`, `decrypt`, `keygen`  

**Run:**
```bash
uv run python main.py <command> [options]
# or if installed
pyranoid <command> [options]
```

## Modes
- **Password Mode:** Encrypt/decrypt with a password  
- **RSA Mode:** Encrypt/decrypt with RSA key pairs  

---

## 1. Key Generation
Generate 4096-bit RSA keys.  
```bash
uv run python main.py keygen [-priv PATH] [-pub PATH]
```
- Prompts to encrypt private key (recommended)  

---

## 2. Encrypt
Hide a file in an image.  
```bash
uv run python main.py encrypt <image> <target> [options]
```
**Options:**  
- `-o PATH` – output image (default: `output.png`)  
- `--public-key PATH` – RSA mode  
- `-p [PASSWORD]` – password mode  

---

## 3. Decrypt
Extract hidden file.  
```bash
uv run python main.py decrypt <image> [options]
```
**Options:**  
- `-d PATH` – output directory  
- `--private-key PATH` – RSA mode  
- `-p [PASSWORD]` – password mode  
- `-k PASSWORD` – RSA key password  

---

## Examples
**Password Mode**
```bash
uv run python main.py encrypt photo.png secret.txt -p -o hidden.png
uv run python main.py decrypt hidden.png -p -d ./output
```

**RSA Mode**
```bash
uv run python main.py keygen
uv run python main.py encrypt photo.png file.pdf --public-key public.pem -o hidden.png
uv run python main.py decrypt hidden.png --private-key private.pem -d ./output
```