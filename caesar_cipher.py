"""
Applies a Caesar substitution cipher, which shifts each letter some number of
positions down the alphabet.

For example, if shifting by 5, the letter "A" becomes "F" and "X" becomes "C".
"""

def encrypt(message, key):
    """Returns the given message encrypted using a Caesar cipher."""
    return apply_cipher(message, key)

def decrypt(message, key):
    """Returns the given message decrypted using a Caesar cipher."""
    return apply_cipher(message, -key)

def apply_cipher(message, shift):
    """Returns the message alphabetically shifted by the given amount."""
    new_message = ""
    for char in message:
        new_message += shift_character(char, shift)

    return new_message

def shift_character(char, shift):
    """Returns the letter alphabetically shifted by the given amount."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"

    # Number, symbol, and whitespace characters stay the same.
    if char.lower() not in alphabet:
        return char

    # Find the character that's 'shift' characters over.
    new_index = alphabet.index(char.lower()) + shift
    shifted_letter = alphabet[new_index % len(alphabet)]

    # Preserve capitalization.
    if char.isupper():
        shifted_letter = shifted_letter.upper()

    return shifted_letter