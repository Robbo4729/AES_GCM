from typing import List

def list_xor(_a: List[int], _b: List[int]) -> List[int]:
    assert len(_a) == len(_b), 'Dimensions of two lists do not match'
    result = []
    for i in range(len(_a)):
        result.append(_a[i] ^ _b[i])
    return result