# author: linzheng tan

from gcm import aes_gcm_encrypt
from gcm_auxiliary import (
    hex_to_list, list_to_hex, string_to_list, 
    list_to_string, xor_bytes
)
from gcm import aes_gcm_encrypt

# 1. prepare the same key and iv
# AES-GCM 128-bit key and 96-bit IV
key = hex_to_list("feffe9928665731c6d6a8f9467308308")  # 16-byte key
iv = hex_to_list("cafebabefacedbaddecaf888")           # reused IV, 12 bytes

# 2. two different plain text
plaintext1 = string_to_list("The message is secure!")  
plaintext2 = string_to_list("We are under attack!")   
known_plaintext = plaintext1

# 3. reused iv
ciphertext1, mac1 = aes_gcm_encrypt(plaintext1, key, iv)  
ciphertext2, mac2 = aes_gcm_encrypt(plaintext2, key, iv)  

# 4. recover plaintext2
xor_cipher_rel = xor_bytes(ciphertext1, ciphertext2)  
recovered_plaintext2 = xor_bytes(known_plaintext, xor_cipher_rel) 

# 5. print result and check correctness
print("Ciphertext 1:", list_to_hex(ciphertext1))
print("Ciphertext 2:", list_to_hex(ciphertext2))
print("Known Plaintext:", list_to_string(plaintext1))
print("Recovered Plaintext 2:", list_to_string(recovered_plaintext2))
print("Original Plaintext 2:", list_to_string(plaintext2))

assert plaintext2 == recovered_plaintext2, "Attack failure!"
print("Attack success!")
