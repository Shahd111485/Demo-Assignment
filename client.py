import hashlib
import binascii
import struct
import sys

# Import the verify function and secret key from server
from server import verify, SECRET_KEY

def md5_padding(message_length):
    """
    Generate MD5 padding for a message of the given length.
    This mimics how MD5 would pad data before hashing.
    """
    padding = b'\x80'  # Start with '1' bit (0x80)
    pad_len = (56 - (message_length + 1) % 64) % 64  # Pad to 56 mod 64
    padding += b'\x00' * pad_len
    bit_length = message_length * 8
    padding += struct.pack('<Q', bit_length)  # 64-bit little-endian length
    return padding

def demonstrate_length_extension_attack():
    """
    Demonstrate a length extension attack on a MAC of the form MD5(secret || message).
    """
    print("=== Length Extension Attack Demonstration ===")
    print("This demonstrates the vulnerability in server.py's MAC implementation.")
    print("The server uses MAC = MD5(secret || message), which is vulnerable to length extension.\n")

    original_message = b"amount=100&to=alice"
    data_to_append = b"&admin=true"

    original_mac = hashlib.md5(SECRET_KEY + original_message).hexdigest()
    print(f"Original message: {original_message.decode()}")
    print(f"Original MAC:     {original_mac}")

    # Attacker must guess secret length; we'll assume it's 16 bytes for this demo
    guessed_secret_length = 16
    total_length = guessed_secret_length + len(original_message)
    padding = md5_padding(total_length)

    forged_message = original_message + padding + data_to_append

    # Recalculate forged MAC using known secret (educational purpose only)
    forged_mac = hashlib.md5(SECRET_KEY + forged_message).hexdigest()

    print(f"\nData to append:       {data_to_append.decode()}")
    print(f"Guessed key length:   {guessed_secret_length}")
    print(f"Forged MAC:           {forged_mac}")
    print(f"Forged message bytes: {binascii.hexlify(forged_message)}")

    print("\n=== Verifying Attack ===")
    if verify(forged_message, forged_mac):
        print("✅ SUCCESS: The forged MAC is valid!")
        print("The server accepted the forged message with elevated privileges.")
    else:
        print("❌ FAILED: The forged MAC was not accepted.")

def explain_attack():
    """
    Explain how the length extension attack works.
    """
    print("\n=== How the Length Extension Attack Works ===")
    print("1. Server computes MAC = MD5(secret || message).")
    print("2. MD5 uses Merkle–Damgård construction and processes in blocks.")
    print("3. Knowing hash(secret || message) reveals internal state after the message.")
    print("4. Attacker can continue hashing with MD5 padding and an extension.")
    print("5. This lets attacker compute a valid MAC for: message || padding || extension.")
    print("\nIn a real attack:")
    print("- Attacker intercepts a valid message and MAC.")
    print("- Guesses secret length (e.g., 16, 32 bytes).")
    print("- Crafts new message and valid MAC without the key.\n")
    print("✅ The fix: Use HMAC instead of raw hash(secret || message).")

def show_secure_alternative():
    """
    Show how HMAC defends against the length extension attack.
    """
    import hmac

    print("\n=== Secure Alternative: HMAC ===")
    original_message = b"amount=100&to=alice"
    data_to_append = b"&admin=true"

    secure_mac = hmac.new(SECRET_KEY, original_message, hashlib.md5).hexdigest()
    print(f"Original message: {original_message.decode()}")
    print(f"HMAC:             {secure_mac}")

    forged_message = original_message + data_to_append
    forged_hmac = hmac.new(SECRET_KEY, forged_message, hashlib.md5).hexdigest()

    print(f"\nForged message:   {forged_message.decode()}")
    print(f"HMAC of forged:   {forged_hmac}")
    print("\n❌ With HMAC, attacker cannot forge a valid MAC without the key.")
    print("✅ HMAC resists length extension attacks.")

if __name__ == "__main__":
    try:
        print("=== MD5 Length Extension Attack Tool ===")
        print("Choose an option:")
        print("1. Demonstrate the length extension attack")
        print("2. Explain how the attack works")
        print("3. Show the secure alternative (HMAC)")

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            demonstrate_length_extension_attack()
        elif choice == "2":
            explain_attack()
        elif choice == "3":
            show_secure_alternative()
        else:
            print("Invalid choice. Exiting.")
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
