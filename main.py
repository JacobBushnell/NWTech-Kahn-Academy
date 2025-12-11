import caesar_cipher
import custom_cipher
import secrets

caesar_key = 19
custom_key = "balderdash"

messages = [
    secrets.text, secrets.location, secrets.password, secrets.passage
]

for message in messages:
    encrypted = caesar_cipher.encrypt(message, caesar_key)
    print(f"Caesar encrypted message: {encrypted}")

    decrypted = caesar_cipher.decrypt(encrypted, caesar_key)
    print(f"Caesar decrypted message: {decrypted}\n")

    encrypted = custom_cipher.encrypt(message, custom_key)
    print(f"Custom encrypted message: {encrypted}")

    decrypted = custom_cipher.decrypt(encrypted, custom_key)
    print(f"Custom decrypted message: {decrypted}\n")
