from gcm import aes_gcm_encrypt

def hex_to_list(hex_str: str):
    """auxiliary function: convert hexadecimal string to list of integers"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def list_to_hex(l: list):
    """auxiliary function: convert list of integers to hexadecimal string"""
    return "".join(f"{b:02x}" for b in l)

def test_aes_gcm():
    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    iv = hex_to_list("cafebabefacedbaddecaf888")
    plaintext = hex_to_list("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = hex_to_list("feedfacedeadbeeffeedfacedeadbeefabaddad2")

    print("--- AES-GCM Encryption Testing begins ---")
    
    ciphertext, mac = aes_gcm_encrypt(plaintext, key, iv, aad)

    print(f"plaintext length: {len(plaintext)} bytes")
    print(f"ciphertext: {list_to_hex(ciphertext)}")
    print(f"MAC (Tag): {list_to_hex(mac)}")

    # validate against standard output reference for this test vector:
    expected_tag = "5bc94fbc3221a5db94fae95ae7121a47"
    
    if list_to_hex(mac) == expected_tag:
        print("\n✅ test succeed！")
        with open("transmit_information.txt", "w") as f:
            f.write(f"ciphertext: {list_to_hex(ciphertext)}\n")
            f.write(f"MAC: {list_to_hex(mac)}\n")
            f.write(f"iv: {list_to_hex(iv)}\n")
            f.write(f"aad: {list_to_hex(aad)}\n")
    else:
        print(f"\n❌ Test failed.")
        print(f"Expected Tag: {expected_tag}")
        print(f"Actual Tag: {list_to_hex(mac)}")
    
if __name__ == "__main__":
    test_aes_gcm()