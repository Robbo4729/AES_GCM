from gcm import aes_gcm_decrypt

def hex_to_list(hex_str: str):
    """auxiliary function: convert hexadecimal string to list of integers"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def list_to_hex(l: list):
    """auxiliary function: convert list of integers to hexadecimal string"""
    return "".join(f"{b:02x}" for b in l)

def decryption_test():
    with open("encrypted_information.txt", "r") as f:
        lines = f.readlines()
        ciphertext = lines[0].split(": ")[1].strip()
        mac = lines[1].split(": ")[1].strip()
        iv = lines[2].split(": ")[1].strip()
        aad = lines[3].split(": ")[1].strip()

    key = hex_to_list("feffe9928665731c6d6a8f9467308308")
    ciphertext_list = hex_to_list(ciphertext)
    mac_list = hex_to_list(mac)
    iv_list = hex_to_list(iv)
    aad_list = hex_to_list(aad)

    print("\n--- AES-GCM Decryption Testing begins ---")
    
    plaintext, is_valid = aes_gcm_decrypt(ciphertext_list, key, iv_list, aad_list, mac_list)

    if is_valid:
        print("✅ Decryption successful and MAC tag is valid.")
        print(f"Decrypted plaintext: {list_to_hex(plaintext)}")
    else:
        print("❌ Decryption failed or MAC tag is invalid.")


if __name__ == "__main__":
    decryption_test()