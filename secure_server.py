import hashlib
import hmac

SECRET_KEY = b'1f8e2b3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1'  # Securely stored in real systems

def generate_mac(message: bytes) -> str:
    """
    Generate a secure HMAC using SHA-256.
    HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
    This construction prevents length extension attacks.
    """
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    """
    Verify the provided MAC using constant-time comparison.
    Prevents timing attacks.
    """
    expected_mac = generate_mac(message)
    return hmac.compare_digest(mac, expected_mac)

def main():
    message = b"amount=100&to=alice"
    mac = generate_mac(message)

    print("=== Secure Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"HMAC: {mac}")

    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("✅ HMAC verified successfully. Message is authentic.\n")

    # Simulate an attacker modifying the message
    forged_message = message + b"&admin=true"
    forged_mac = mac  # Attacker reuses original MAC (this should fail)

    print("--- Verifying forged message with original MAC ---")
    if verify(forged_message, forged_mac):
        print("❌ HMAC verified (unexpected).")
    else:
        print("✅ HMAC verification failed, as expected with secure HMAC.")

    # Prompt for user-supplied forged MAC
    print("\n--- Testing against length extension attack ---")
    try:
        user_forged_mac = input("Enter forged MAC from client.py: ").strip()
        simplified_forged_message = message + b"&admin=true"

        print("Testing with a simplified forged message (no padding):")
        if verify(simplified_forged_message, user_forged_mac):
            print("❌ WARNING: HMAC verification succeeded. This shouldn't happen!")
        else:
            print("✅ SECURE: HMAC verification failed, as expected.")
            
        print("\nNote: Real forged messages often include hash padding.")
        print("But HMAC protects against length extension regardless of padding.")
    except KeyboardInterrupt:
        print("\n[Skipped forged MAC test]")

if __name__ == "__main__":
    main()
