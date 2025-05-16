import hashlib
import hmac  # For secure comparison

# Secret key (unknown to attacker)
SECRET_KEY = b'1f8e2b3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1'

def generate_mac(message: bytes) -> str:
    """
    Generate a MAC using a naive and vulnerable approach:
    MAC = MD5(secret || message)
    """
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    """
    Verify whether the provided MAC matches the expected MAC.
    Note: Now uses constant-time comparison to prevent timing attacks.
    """
    expected_mac = generate_mac(message)
    return hmac.compare_digest(mac, expected_mac)

def main():
    message = b"amount=100&to=alice"
    mac = generate_mac(message)

    print("=== Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")

    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("✅ MAC verified successfully. Message is authentic.\n")

    # Simulated forged message
    forged_message = b"amount=100&to=alice" + b"&admin=true"
    forged_mac = mac  # Attacker just reuses the MAC

    print("--- Verifying forged message ---")
    if verify(forged_message, forged_mac):
        print("❌ MAC verified (unexpected).")
    else:
        print("✅ MAC verification failed (as expected).")

if __name__ == "__main__":
    main()
