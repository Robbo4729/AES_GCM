from typing import List, Tuple
from aes import aes128
from gcm_auxiliary import int_to_list, xor_bytes, pad_16, inc32
from ghash import gcm_gf_mult

def aes_gcm_encrypt(plaintext: List[int], key: List[int], iv: List[int], aad: List[int] = []) -> Tuple[List[int], List[int]]:
    """
    AES-128-GCM encryption function
    
    param:
        plaintext: (List[int])
        key: (List[int])
        iv: (List[int])
        aad: (List[int]): Optional, Additional Authenticated Data (AAD), which is the data that will be authenticated but not encrypted. It can be empty.
        
    return:
        (ciphertext, MAC)
    """
    assert len(key) == 16, 'AES-128 key must be 16 bytes'
    assert len(iv) == 12, 'IV must be 12 bytes in this standard implementation'

    h = aes128([0] * 16, key)

    # J0 = Nonce(12bytes Nonce) + Counter(4 bytes)
    J0 = iv + [0, 0, 0, 1]
    counter = J0.copy()

    # CTR mode encryption
    ciphertext = []
    # Seperate plaintext into 16-byte blocks and encrypt each block
    for i in range(0, len(plaintext), 16):
        counter = inc32(counter) # Increase counter for each block
        keystream = aes128(counter, key)
        block = plaintext[i:i+16]
        # XOR plaintext block with keystream to get ciphertext block 
        ciphertext.extend(xor_bytes(block, keystream))

    # Compute GHASH for authentication tag
    X = [0] * 16
    
    # Incorporate AAD into GHASH
    padded_aad = pad_16(aad)
    for i in range(0, len(padded_aad), 16):
        X = gcm_gf_mult(xor_bytes(X, padded_aad[i:i+16]), h)
        
    # Incorporate Ciphertext into GHASH
    padded_ciphertext = pad_16(ciphertext)
    for i in range(0, len(padded_ciphertext), 16):
        X = gcm_gf_mult(xor_bytes(X, padded_ciphertext[i:i+16]), h)

    # Incorporate lengths of AAD and Ciphertext into GHASH(64 bits/8 bytes for each)
    len_block = int_to_list(len(aad) * 8, 8) + int_to_list(len(ciphertext) * 8, 8)
    X = gcm_gf_mult(xor_bytes(X, len_block), h)
    # Derive the final MAC tag by XORing GHASH output with E(J0)
    E_J0 = aes128(J0, key)      
    mac = xor_bytes(X, E_J0)

    return ciphertext, mac

def aes_gcm_decrypt(ciphertext: List[int], key: List[int], iv: List[int], aad: List[int] = [], mac: List[int] = []) -> Tuple[List[int], bool]:
    """
    AES-128-GCM decryption function
    
    param:
        ciphertext: (List[int])
        key: (List[int])
        iv: (List[int])
        aad: (List[int]): Optional, Additional Authenticated Data (AAD), which is the data that will be authenticated but not encrypted. It can be empty.
        mac: (List[int]): The authentication tag to verify against.
        
    return:
        (plaintext, is_valid)
    """
    # Decryption process is similar to encryption, but we also need to verify the MAC tag
    assert len(key) == 16, 'AES-128 key must be 16 bytes'
    assert len(iv) == 12, 'IV must be 12 bytes in this standard implementation'

    h = aes128([0] * 16, key)

    # Compute GHASH for authentication tag
    X = [0] * 16
    J0 = iv + [0, 0, 0, 1]
    
    # Incorporate AAD into GHASH
    padded_aad = pad_16(aad)
    for i in range(0, len(padded_aad), 16):
        X = gcm_gf_mult(xor_bytes(X, padded_aad[i:i+16]), h)
        
    # Incorporate Ciphertext into GHASH
    padded_ciphertext = pad_16(ciphertext)
    for i in range(0, len(padded_ciphertext), 16):
        X = gcm_gf_mult(xor_bytes(X, padded_ciphertext[i:i+16]), h)

    # Incorporate lengths of AAD and Ciphertext into GHASH(64 bits/8 bytes for each)
    len_block = int_to_list(len(aad) * 8, 8) + int_to_list(len(ciphertext) * 8, 8)
    X = gcm_gf_mult(xor_bytes(X, len_block), h)
    # Derive the final MAC tag by XORing GHASH output with E(J0)
    E_J0 = aes128(J0, key)
    pend_mac = xor_bytes(X, E_J0)

    # Compare computed MAC with provided MAC
    is_valid = pend_mac == mac

    # If valid, proceed to decrypt the ciphertext
    plaintext = []
    if is_valid:
        counter = J0.copy()
        for i in range(0, len(ciphertext), 16):
            counter = inc32(counter) # Increase counter for each block
            keystream = aes128(counter, key)
            block = ciphertext[i:i+16]
            # XOR ciphertext block with keystream to get plaintext block 
            plaintext.extend(xor_bytes(block, keystream))

    if plaintext is not None:
        plaintext = bytes(plaintext).decode("utf-8")

    return plaintext, is_valid