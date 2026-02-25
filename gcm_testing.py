from gcm import aes_gcm_encrypt
from Crypto.Random import get_random_bytes

def hex_to_list(hex_str: str):
    """auxiliary function: convert hexadecimal string to list of integers"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def list_to_hex(l: list):
    """auxiliary function: convert list of integers to hexadecimal string"""
    return "".join(f"{b:02x}" for b in l)

def string_to_list(s: str):
    return list(s.encode("utf-8"))

def test_aes_gcm():
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    iv = hex_to_list("cafebabefacedbaddecaf888")
    aad = hex_to_list("feedfacedeadbeeffeedfacedeadbeefabaddad2")

    with open("plaintext.txt", "r") as f:
        lines = f.readlines()
        plaintext = string_to_list(lines[0].strip())

    print("--- AES-GCM Encryption Testing begins ---")
    
    ciphertext, mac = aes_gcm_encrypt(plaintext, key, iv, aad)

    print(f"Encryption successful!")
    print(f"ciphertext: {list_to_hex(ciphertext)}")
    print(f"MAC (Tag): {list_to_hex(mac)}")

    with open("encrypted_information.txt", "w") as f:
        f.write(f"ciphertext: {list_to_hex(ciphertext)}\n")
        f.write(f"MAC: {list_to_hex(mac)}\n")
        f.write(f"iv: {list_to_hex(iv)}\n")
        f.write(f"aad: {list_to_hex(aad)}\n")

if __name__ == "__main__":
    test_aes_gcm()