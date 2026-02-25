from Crypto.Cipher import AES

def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def string_to_bytes(s: str) -> bytes:
    return s.encode("utf-8")

def official_test():
    key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    iv = hex_to_bytes("cafebabefacedbaddecaf888")
    # iv = hex_to_list(get_random_bytes(12).hex())  # 96-bit IV, can be random for testing
    # plaintext = hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")

    with open("plaintext.txt", "r") as f:
        lines = f.readlines()
        plaintext = string_to_bytes(lines[0].strip())

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=iv
    )

    cipher.update(aad)
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)

    ciphertext_list = bytes_to_hex(ciphertext)
    mac_list = bytes_to_hex(mac)

    print("Ciphertext:", ciphertext_list)
    print("Tag:", mac_list)

if __name__ == "__main__":
    official_test()
