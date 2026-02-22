from typing import List

def list_to_int(l: List[int]) -> int:
    """convert a list of bytes (integers) to a single large integer"""
    return int.from_bytes(bytes(l), byteorder='big')

def int_to_list(n: int, length: int) -> List[int]:
    """convert a large integer to a list of bytes (integers) of specified length"""
    return list(n.to_bytes(length, byteorder='big'))

def xor_bytes(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]

def pad_16(data: List[int]) -> List[int]:
    """pad data to a multiple of 16 bytes (128 bits)"""
    rem = len(data) % 16
    if rem == 0:
        return data.copy()
    return data + [0] * (16 - rem)

def inc32(block: List[int]) -> List[int]:
    """Increment the last 32 bits of the block (counter)"""
    counter = list_to_int(block[12:16])
    counter = (counter + 1) & 0xFFFFFFFF
    return block[:12] + int_to_list(counter, 4)
