from typing import List
from gcm_auxiliary import list_to_int, int_to_list

# GF(2^128) Algorithm for GCM (GHASH)
def gcm_gf_mult(x: List[int], y: List[int]) -> List[int]:
    """
    GCM GF(2^128) multiplication function
    """
    X = list_to_int(x)
    Y = list_to_int(y)
    R = 0xe1000000000000000000000000000000   # P(x) = x^128 + x^7 + x^2 + x + 1 
    Z = 0
    V = Y
    for i in range(128):
        # Check if the i-th bit of X is set, if so XOR Z with V
        if (X >> (127 - i)) & 1:
            Z ^= V
        # Check if the least significant bit of V is set, if so right shift V and XOR with R
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V >>= 1
    return int_to_list(Z, 16)