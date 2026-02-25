from gcm import aes_gcm_decrypt
from gcm_auxiliary import hex_to_list

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
        print("Decryption successful and MAC tag is valid.")
        print(f"Decrypted plaintext: {plaintext}")
    else:
        print("Decryption failed or MAC tag is invalid.")


if __name__ == "__main__":
    decryption_test()