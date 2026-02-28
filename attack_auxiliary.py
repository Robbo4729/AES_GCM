# author: linzheng tan

from typing import List, Optional
from ghash import gcm_gf_mult
from gcm_auxiliary import int_to_list, xor_bytes

# --- GF(2^128) Arithmetic Utilities ---

def list_to_int(l: List[int]) -> int:
    val = 0
    for b in l:
        val = (val << 8) | b
    return val

def gf_pow(x_list: List[int], power: int) -> List[int]:
    res = [0x80] + [0] * 15 # GCM Identity: 1 is 0x8000...
    base = list(x_list)
    p = power
    while p > 0:
        if p % 2 == 1:
            res = gcm_gf_mult(res, base)
        base = gcm_gf_mult(base, base)
        p //= 2
    return res

def gf_inverse(a_list: List[int]) -> List[int]:
    return gf_pow(a_list, (1 << 128) - 2)

def gf_sqrt(a_list: List[int]) -> List[int]:
    """Calculate Square Root using Fermat's Little Theorem: a^(2^127)"""
    power: int = 1 << 127
    return gf_pow(a_list, power)

# --- Linear Algebra Solver for x^2 + x = k ---

def build_linear_map_matrix() -> List[int]:
    """Constructs 128x128 matrix M for linear map L(z) = z^2 + z."""
    matrix = []
    for i in range(128):
        # Basis vector e_i (integer with i-th bit set)
        e_i_int = 1 << (127 - i)
        e_i = int_to_list(e_i_int, 16)
        
        # Calculate L(e_i) = e_i^2 + e_i
        sq = gcm_gf_mult(e_i, e_i)
        val = list_to_int(sq) ^ e_i_int
        matrix.append(val)
    return matrix

def solve_linear_system_gf2(matrix_rows: List[int], k_val: int) -> Optional[int]:
    """Gaussian elimination to solve M * z = k."""
    n = 128
    M = list(matrix_rows)
    K = [(k_val >> (127 - i)) & 1 for i in range(n)]
    
    pivot_row_map = {} 

    # Forward Elimination
    curr_row = 0
    for col in range(n):
        if curr_row >= n: break
        
        pivot = -1
        for r in range(curr_row, n):
            if (M[r] >> (127 - col)) & 1:
                pivot = r
                break
        
        if pivot == -1: continue 
        
        # Swap rows
        M[curr_row], M[pivot] = M[pivot], M[curr_row]
        K[curr_row], K[pivot] = K[pivot], K[curr_row]
        
        # Eliminate
        for r in range(n):
            if r != curr_row:
                if (M[r] >> (127 - col)) & 1:
                    M[r] ^= M[curr_row]
                    K[r] ^= K[curr_row]
        
        pivot_row_map[col] = curr_row
        curr_row += 1

    # Check consistency
    for r in range(curr_row, n):
        if K[r] != 0: return None 

    # Extract solution
    z = 0
    for col in range(n):
        if col in pivot_row_map:
            r = pivot_row_map[col]
            if K[r]:
                z |= (1 << (127 - col))
    return z

def solve_quadratic_gf2_128(a: List[int], b: List[int], c: List[int]) -> List[List[int]]:
    """
    Solves ax^2 + bx + c = 0 in GF(2^128).
    Returns a list of solutions. usually [x1, x2].
    If no solution, returns [].
    """
    # 1. Linear Case (Degenerate)
    if list_to_int(a) == 0:
        if list_to_int(b) == 0: return []
        return [gcm_gf_mult(c, gf_inverse(b))]

    # 2. Setup Transform
    inv_a = gf_inverse(a)
    u = gcm_gf_mult(b, inv_a)      # u = b/a
    v = gcm_gf_mult(c, inv_a)      # v = c/a
    
    # K = v / u^2
    u2 = gcm_gf_mult(u, u)
    inv_u2 = gf_inverse(u2)
    K_list = gcm_gf_mult(v, inv_u2)
    K_int = list_to_int(K_list)

    # 3. Solve z^2 + z = K via Matrix
    col_vecs = build_linear_map_matrix()
    rows = [0] * 128
    for j in range(128): 
        val = col_vecs[j]
        for i in range(128):
            if (val >> (127 - i)) & 1:
                rows[i] |= (1 << (127 - j))
    
    z_int = solve_linear_system_gf2(rows, K_int)
    
    if z_int is None: return [] # No solution

    # 4. Map back to x1
    z_list = int_to_list(z_int, 16)
    x1 = gcm_gf_mult(u, z_list)
    
    # 5. Calculate x2
    # The other root for z^2+z=K is z+1.
    # So the other root for x is u*(z+1) = u*z + u = x1 + u.
    # In GF(2^128), addition is XOR.
    x2 = xor_bytes(x1, u)
    
    return [x1, x2]
