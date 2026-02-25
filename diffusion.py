# GF(2^8) multiplication
def gf_mul(a, b):
    """
    Multiply two bytes in GF(2^8) with AES modulus     x^8 + x^4 + x^3 + x + 1 (0x11B).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


def shift_rows(state):
    """
    Row-wise cyclic left shift.
    """
    new_state = state.copy()

    for row in range(4):
        indices = [row + 4*c for c in range(4)]
        values = [state[i] for i in indices]
        values = values[row:] + values[:row]
        for idx, val in zip(indices, values):
            new_state[idx] = val

    return new_state


def mix_column(col):
    """
    Mix one AES column (4 bytes).
    """
    a0, a1, a2, a3 = col
    return [
        gf_mul(2,a0) ^ gf_mul(3,a1) ^ a2 ^ a3,
        a0 ^ gf_mul(2,a1) ^ gf_mul(3,a2) ^ a3,
        a0 ^ a1 ^ gf_mul(2,a2) ^ gf_mul(3,a3),
        gf_mul(3,a0) ^ a1 ^ a2 ^ gf_mul(2,a3)
    ]


def mix_columns(state):
    """
    Apply MixColumns to all columns.
    """
    new_state = state.copy()

    for c in range(4):
        idx = [r + 4*c for r in range(4)]
        col = [state[i] for i in idx]
        mixed = mix_column(col)
        for i, v in zip(idx, mixed):
            new_state[i] = v

    return new_state


def diffusion(state):
    """
    Apply ShiftRows then MixColumns.
    """
    state = shift_rows(state)
    state = mix_columns(state)
    return state
