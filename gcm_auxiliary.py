from typing import List

def list_to_int(l: List[int]) -> int:
    """convert a list of bytes (integers) to a single large integer"""
    return int.from_bytes(bytes(l), byteorder='big')

def int_to_list(n: int, length: int) -> List[int]:
    """convert a large integer to a list of bytes (integers) of specified length"""
    return list(n.to_bytes(length, byteorder='big'))

def hex_to_list(hex_str: str):
    """auxiliary function: convert hexadecimal string to list of integers"""
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def list_to_hex(l: list):
    """auxiliary function: convert list of integers to hexadecimal string"""
    return "".join(f"{b:02x}" for b in l)

def string_to_list(s: str):
    return list(s.encode("utf-8"))

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
