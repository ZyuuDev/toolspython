import base64, binascii, urllib.parse, string, os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from colorama import Fore, Style, init

# Inisialisasi warna di console
init(autoreset=True)

# -----------------------------
# Helper functions
# -----------------------------
def to_bytes(text: str):
    return text.encode('utf-8')

def to_str(b: bytes):
    return b.decode('utf-8', errors='ignore')


# -----------------------------
# 1. Base64
# -----------------------------
def base64_enc(text):
    return base64.b64encode(to_bytes(text)).decode()

def base64_dec(text):
    return to_str(base64.b64decode(text))


# -----------------------------
# 2. Hex
# -----------------------------
def hex_enc(text):
    return to_bytes(text).hex()

def hex_dec(text):
    return to_str(bytes.fromhex(text))


# -----------------------------
# 3. Binary
# -----------------------------
def binary_enc(text):
    return ' '.join(format(b, '08b') for b in to_bytes(text))

def binary_dec(bits):
    try:
        return to_str(bytes(int(b, 2) for b in bits.split()))
    except:
        raise ValueError("Invalid binary input")


# -----------------------------
# 4. URL Encode
# -----------------------------
def url_enc(text):
    return urllib.parse.quote(text)

def url_dec(text):
    return urllib.parse.unquote(text)


# -----------------------------
# 5. ROT13
# -----------------------------
def rot13(text):
    trans = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    return text.translate(trans)


# -----------------------------
# 6. Caesar Cipher
# -----------------------------
def caesar(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)


# -----------------------------
# 7. Atbash Cipher
# -----------------------------
def atbash(text):
    table = str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1],
    )
    return text.translate(table)


# -----------------------------
# 8. XOR Cipher (base64 output)
# -----------------------------
def xor_hex_dec(hex_text, key):
    if not key:
        raise ValueError("Key required for XOR")

    data = bytes.fromhex(hex_text)
    key_bytes = to_bytes(key)

    dec = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
    return to_str(dec)


def xor_dec(b64text, key):
    if not key:
        raise ValueError("Key required for XOR")
    data = base64.b64decode(b64text)
    key_bytes = to_bytes(key)
    dec = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
    return to_str(dec)


# -----------------------------
# 9. UTF-8 Hex
# -----------------------------
def utf8hex_enc(text):
    return to_bytes(text).hex()

def utf8hex_dec(text):
    return to_str(bytes.fromhex(text))


# -----------------------------
# 10. AES-GCM (secure)
# -----------------------------
def aes_encrypt(plaintext, password):
    salt = get_random_bytes(16)
    iv = get_random_bytes(12)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(to_bytes(plaintext))
    payload = b':'.join([
        base64.b64encode(salt),
        base64.b64encode(iv),
        base64.b64encode(ciphertext),
        base64.b64encode(tag)
    ])
    return payload.decode()

def aes_decrypt(payload, password):
    try:
        salt_b64, iv_b64, ct_b64, tag_b64 = payload.split(':')
        salt, iv, ct, tag = map(base64.b64decode, [salt_b64, iv_b64, ct_b64, tag_b64])
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        return to_str(plaintext)
    except Exception as e:
        raise ValueError(f"Decrypt failed: {e}")


# -----------------------------
# Tampilan CLI
# -----------------------------
def banner():
    os.system('clear')
    print(Fore.CYAN + Style.BRIGHT + r"""
 ████████╗ ██████╗  ██████╗ ██╗     ███████╗███████╗████████╗
 ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝██╔════╝╚══██╔══╝
    ██║   ██║   ██║██║   ██║██║     █████╗  ███████╗   ██║   
    ██║   ██║   ██║██║   ██║██║     ██╔══╝  ╚════██║   ██║   
    ██║   ╚██████╔╝╚██████╔╝███████╗███████╗███████║   ██║   
    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝   

             🔐  ENCRYPT-DECRYPT TOOL  🔐
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + " [🧩 Supported Methods]" + Fore.WHITE + ": base64, hex, binary, url, rot13, caesar, atbash, xor, utf8hex, aes")
    print(Fore.YELLOW + " [⚙️  Usage]" + Fore.WHITE + ": pilih mode (enc/dec) dan metode lalu masukkan teks")
    print(Fore.MAGENTA + "───────────────────────────────────────────────────────────────")


if __name__ == "__main__":
    banner()

    mode = input(Fore.CYAN + "Mode (enc/dec): " + Fore.WHITE).strip()
    method = input(Fore.CYAN + "Metode: " + Fore.WHITE).strip().lower()
    text = input(Fore.CYAN + "Teks: " + Fore.WHITE)
    param = input(Fore.CYAN + "Parameter (key/shift/password bila perlu): " + Fore.WHITE)

    try:
        if method == "base64":
            out = base64_enc(text) if mode == "enc" else base64_dec(text)
        elif method == "hex":
            out = hex_enc(text) if mode == "enc" else hex_dec(text)
        elif method == "binary":
            out = binary_enc(text) if mode == "enc" else binary_dec(text)
        elif method == "url":
            out = url_enc(text) if mode == "enc" else url_dec(text)
        elif method == "rot13":
            out = rot13(text)
        elif method == "caesar":
            shift = int(param or 0)
            out = caesar(text, shift if mode == "enc" else -shift)
        elif method == "atbash":
            out = atbash(text)
        elif method == "xor":
            out = xor_enc(text, param) if mode == "enc" else xor_dec(text, param)
        elif method == "utf8hex":
            out = utf8hex_enc(text) if mode == "enc" else utf8hex_dec(text)
        elif method == "aes":
            out = aes_encrypt(text, param) if mode == "enc" else aes_decrypt(text, param)
        else:
            raise ValueError("Metode tidak dikenal")

        print(Fore.GREEN + "\n[✅ HASIL] " + Fore.WHITE + out + "\n")

    except Exception as e:
        print(Fore.RED + f"\n[❌ ERROR] {e}\n")
