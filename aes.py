# Author: Fang Zihao
from typing import List
from key_expansion import key_expansion
from confusion import byte_substitution
from diffusion import diffusion, shift_rows
from aes_auxiliary import list_xor

def aes128(plaintext: List[int], key: List[int]) -> List[int]:
    assert len(plaintext) == 16, 'Dimension of plaintext is not 16'
    assert len(key) == 16, 'Dimension of key is not 16'
    keys = key_expansion(key)
    result = plaintext.copy()
    # Add round key
    result = list_xor(plaintext, keys[0])
    for i in range(9):
        # S-box
        result = byte_substitution(result)
        # Shift rows & Mix columns
        result = diffusion(result)
        # Add round key
        result = list_xor(result, keys[i + 1])
    # S-box
    result = byte_substitution(result)
    # Shift rows
    result = shift_rows(result)
    # Add round key
    result = list_xor(result, keys[10])
    return result
    
    