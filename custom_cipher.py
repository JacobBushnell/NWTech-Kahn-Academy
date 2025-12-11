"""Applies your custom cipher algorithm."""
# Import the built-in hashlib module for cryptographic hash functions
# and string for the uppercase alphabet
import hashlib
import string

def key_to_shift_stream(key: str, length: int) -> list[int]:
    """Generate pseudo-random shifts (0–25) from the key"""
    stream = []
    counter = 0
    while len(stream) < length:
        data = f"{key}{counter}".encode()
        digest = hashlib.sha256(data).digest()
        for byte in digest:
            stream.append(byte % 26)
            if len(stream) >= length:
                break
        counter += 1
    return stream

def encrypt(message: str, key: str) -> str:
    """Encrypt only English letters (A–Z, a–z), leave everything else untouched"""
    shifts = key_to_shift_stream(key, len(message))
    result = []

    for i, char in enumerate(message):
        # Check if it's an English letter (uppercase or lowercase)
        if 'A' <= char <= 'Z':
            # Uppercase letter
            pos = ord(char) - ord('A')                  # A=0, B=1, ..., Z=25
            new_pos = (pos + shifts[i]) % 26
            encrypted_char = chr(ord('A') + new_pos)
            result.append(encrypted_char)
        elif 'a' <= char <= 'z':
            # Lowercase letter
            pos = ord(char) - ord('a')
            new_pos = (pos + shifts[i]) % 26
            encrypted_char = chr(ord('a') + new_pos)
            result.append(encrypted_char)
        else:
            # Not an English letter → leave completely unchanged
            # This includes: é, ñ, ü, 汉, 😊, 123, spaces, punctuation, etc.
            result.append(char)
    
    return ''.join(result)


def decrypt(message: str, key: str) -> str:
    """Decrypt only English letters, leave everything else unchanged"""
    shifts = key_to_shift_stream(key, len(message))
    result = []

    for i, char in enumerate(message):
        if 'A' <= char <= 'Z':
            pos = ord(char) - ord('A')
            original_pos = (pos - shifts[i]) % 26
            original_char = chr(ord('A') + original_pos)
            result.append(original_char)
        elif 'a' <= char <= 'z':
            pos = ord(char) - ord('a')
            original_pos = (pos - shifts[i]) % 26
            original_char = chr(ord('a') + original_pos)
            result.append(original_char)
        else:
            result.append(char)
    
    return ''.join(result)