# Author: Fang Zihao
from typing import List
from confusion import byte_substitution
from aes_auxiliary import list_xor

RCon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key: List[int]) -> List[List[int]]:
    assert len(key) == 16, 'Dimension of key is not 16'
    result = [key.copy()]
    for i in range(10):
        nextkey = result[-1].copy()
        # Step 1: Shift
        w3 = nextkey[12:]
        w3 = w3[1:] + [w3[0]]
        w3 = byte_substitution(w3)
        w3[0] ^= RCon[i]
        w0 = list_xor(nextkey[0:4], w3)
        w1 = list_xor(nextkey[4:8], w0)
        w2 = list_xor(nextkey[8:12], w1)
        w3 = list_xor(nextkey[12:16], w2)
        result.append(w0 + w1 + w2 + w3)
    return result