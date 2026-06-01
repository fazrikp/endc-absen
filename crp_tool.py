import os
import sys
import argparse
import struct
import hashlib
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

DEFAULT_AES_PASSWORD = "myKey123"


def normalize_aes_key(key):
    if key is None:
        return None
    if isinstance(key, bytes):
        key_bytes = key
    else:
        key_bytes = key.encode("utf-16-le")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("Key AES harus menghasilkan 16, 24, atau 32 byte setelah UTF-16LE")
    return key_bytes


def build_aes_cipher(key, iv=None, mode="cbc"):
    key_bytes = normalize_aes_key(key)
    mode_name = mode.lower()
    if mode_name not in ("cbc", "ecb"):
        raise ValueError("Mode AES hanya mendukung cbc atau ecb")
    if mode_name == "cbc":
        iv_bytes = key_bytes[:16] if iv is None else iv
        if len(iv_bytes) != 16:
            raise ValueError("IV AES CBC harus 16 byte")
        cipher_mode = modes.CBC(iv_bytes)
    else:
        cipher_mode = modes.ECB()
    return Cipher(algorithms.AES(key_bytes), cipher_mode, backend=default_backend())


def pkcs7_pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def hex_dump(data, length=16):
    """Menampilkan data dalam format hex dump"""
    result = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        result.append(f"{i:08X}  {hex_part:<{length*3}}  {ascii_part}")
    return "\n".join(result)

def calculate_entropy(data):
    """Menghitung entropy file (0-8). >7.5 biasanya terenkripsi kuat"""
    if not data: return 0
    freq = [0]*256
    for b in data: freq[b] += 1
    ent = 0.0
    for f in freq:
        if f == 0: continue
        p = f / len(data)
        ent -= p * math.log2(p)
    return ent

def analyze_crp(filepath):
    """Analisis struktur file .crp"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"📁 File: {filepath}")
    print(f"📏 Size: {len(data)} bytes")
    print(f" Entropy: {calculate_entropy(data):.2f}/8.00")
    print("\n🔍 First 64 bytes (HEX DUMP):")
    print(hex_dump(data[:64]))
    
    # Cek header umum
    if data[:4] == b'CRYP' or data[:4] == b'P208':
        print("✅ Header terdeteksi: CRYP/P208 (kemungkinan AES-CBC)")
    elif data[:2] == b'\x00\x01' or data[:2] == b'\x55\xAA':
        print("✅ Kemungkinan format biner custom atau XOR")
    else:
        print("⚠️ Header tidak dikenal. Coba brute-force XOR atau AES.")

def xor_decrypt(data, key_byte):
    return bytes([b ^ key_byte for b in data])

def aes_decrypt(data, key, iv=None, mode='cbc'):
    cipher = build_aes_cipher(key, iv=iv, mode=mode)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return pkcs7_unpad(plaintext)

def aes_encrypt(plaintext, key, iv=None, mode='cbc'):
    cipher = build_aes_cipher(key, iv=iv, mode=mode)
    encryptor = cipher.encryptor()
    padded_plaintext = pkcs7_pad(plaintext)
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def looks_like_attendance_text(data):
    sample = data[:4096]
    if b"," not in sample or b"/" not in sample:
        return False
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return False
    return sum(line[:3].isdigit() and "," in line for line in lines[:10]) >= max(1, len(lines[:10]) // 2)

def try_brute_xor(data):
    """Coba semua key XOR 0-255, kembalikan yang menghasilkan teks valid"""
    results = []
    for key in range(256):
        dec = xor_decrypt(data, key)
        # Cek apakah >80% karakter printable ASCII
        printable = sum(32 <= b <= 126 or b in (10, 13, 9) for b in dec[:256])
        if printable > len(dec[:256]) * 0.75:
            results.append((key, dec))
    return results

def process_file(input_path, output_path, mode='decrypt', method='auto', key=None, xor_key=None):
    with open(input_path, 'rb') as f:
        data = f.read()

    decrypted = b""
    if mode == 'decrypt':
        if method == 'auto':
            print("🔄 Mencoba auto-detect metode...")
            # 1. Coba XOR brute
            xor_res = try_brute_xor(data)
            if xor_res:
                print(f"✅ XOR Key ditemukan: 0x{xor_res[0][0]:02X}")
                decrypted = xor_res[0][1]
                method = 'xor'
            else:
                # 2. Coba AES dengan key umum P208
                common_keys = [DEFAULT_AES_PASSWORD, "1234567890123456", "admin12345678901", "P208FINGERPRINT0", "0000000000000000"]
                for ck in common_keys:
                    try:
                        decrypted = aes_decrypt(data, ck)
                        if looks_like_attendance_text(decrypted):
                            print(f"✅ AES Key cocok: {ck}")
                            method = 'aes'
                            break
                    except: continue
                if decrypted == b"":
                    raise ValueError("Gagal auto-detect. Coba --method aes --key myKey123 atau --method xor --xor-key N")
        elif method == 'xor':
            if xor_key is None: xor_key = 0x55  # Default umum
            decrypted = xor_decrypt(data, xor_key)
        elif method == 'aes':
            if key is None: raise ValueError("Key AES wajib diisi untuk mode aes")
            decrypted = aes_decrypt(data, key)
    elif mode == 'encrypt':
        if method == 'xor':
            k = xor_key if xor_key else 0x55
            decrypted = xor_decrypt(data, k)  # XOR symmetric
        elif method == 'aes':
            if key is None:
                key = DEFAULT_AES_PASSWORD
            decrypted = aes_encrypt(data, key)

    with open(output_path, 'wb') as f:
        f.write(decrypted)
    print(f"✅ {mode.capitalize()} selesai → {output_path}")
    if mode == 'decrypt' and looks_like_attendance_text(decrypted):
        print("📄 Format attendance terdeteksi. Siap diolah.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P208 CRP Encrypt/Decrypt Tool")
    parser.add_argument("input", help="File input (.crp atau .txt)")
    parser.add_argument("output", help="File output")
    parser.add_argument("--mode", choices=["decrypt", "encrypt"], default="decrypt")
    parser.add_argument("--method", choices=["auto", "aes", "xor"], default="auto")
    parser.add_argument("--key", help="Key AES (16/24/32 char)")
    parser.add_argument("--xor-key", type=int, help="Key XOR (0-255)")
    parser.add_argument("--analyze", action="store_true", help="Hanya analisis file .crp")
    args = parser.parse_args()

    if args.analyze:
        analyze_crp(args.input)
    else:
        process_file(args.input, args.output, args.mode, args.method, args.key, args.xor_key)