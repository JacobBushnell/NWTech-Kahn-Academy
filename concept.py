# Import the built-in hashlib module for cryptographic hash functions
# and string for the uppercase alphabet
import hashlib
import string

# build the cipher to alternate a simple math problem for each letter in the key to represent a seed digit. 
# then take the last digit of the value to represent an alphabet charecter.

def key_to_shift_stream(key: str, length: int = 1000) -> list[int]:
    """
    Generate a long sequence of pseudo-random numbers (0–25) from a passphrase.
    This will be used as shifting amounts for each letter (like a running key).
    """
    stream = []                    # This list will hold all the shift values (0–25)
    counter = 0                    # A counter to make every hash input unique

    # Keep generating hashes until we have enough shift numbers
    while len(stream) < length:
        # Create a unique input for the hash: passphrase + counter
        # Example: "MySecret123" → "MySecret1230", "MySecret1231", etc.
        hash_input = f"{key}{counter}".encode()   # Convert string → bytes (required by hashlib)

        # Compute SHA-256 hash of the input and get it as a 64-character hex string
        digest = hashlib.sha256(hash_input).hexdigest()   # e.g. "a3f1e9...c0"

        # The hex digest has 64 characters → 32 bytes of data when interpreted as hex
        # We process it two characters at a time → one byte (00 to FF → 0–255)
        for i in range(0, len(digest), 2):        # Step by 2: 0,2,4,...
            two_chars = digest[i:i+2]             # Take two hex digits: e.g. "a3", "f1"
            value = int(two_chars, 16)            # Convert hex → integer: "a3" → 163
            shift = value % 26                    # Reduce to 0–25 range (perfect for alphabet)
            stream.append(shift)                  # Add this shift value to our sequence

            # Stop early if we already have enough shifts
            if len(stream) >= length:
                break

        counter += 1  # Increase counter so the next hash is completely different

    return stream     # Return the list of shift amounts


def encrypt(message: str, key: str) -> str:
    """Encrypt message using the key-derived varying Caesar shift"""
    # Remove all non-letter characters and convert to uppercase
    message = ''.join(c.upper() for c in message if c.isalpha())

    # Generate exactly as many shift numbers as we have letters
    shifts = key_to_shift_stream(key, len(message))

    alphabet = string.ascii_uppercase    # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []                          # Will collect encrypted letters

    # Go through each letter and its position
    for i, c in enumerate(message):
        if c in alphabet:                # Safety check (should always be true here)
            # Find position in alphabet (A=0, B=1, ..., Z=25)
            plain_pos = alphabet.index(c)
            # Add the pseudo-random shift for this position
            new_pos = (plain_pos + shifts[i]) % 26
            # Get the new letter and add it to result
            result.append(alphabet[new_pos])

    # Join all encrypted letters into one string and return
    return ''.join(result)


def decrypt(message: str, key: str) -> str:
    """Decrypt message using the same key (generates identical shift sequence)"""
    message = message.upper()      # Make sure everything is uppercase

    # Generate the exact same shift sequence as during encryption
    shifts = key_to_shift_stream(key, len(message))

    alphabet = string.ascii_uppercase
    result = []

    for i, c in enumerate(message):
        if c in alphabet:
            cipher_pos = alphabet.index(c)
            # Subtract the same shift we added during encryption
            original_pos = (cipher_pos - shifts[i]) % 26
            result.append(alphabet[original_pos])

    return ''.join(result)
