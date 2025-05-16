# Background: Message Authentication Codes and Length Extension Attacks

## What is a MAC and its Purpose?

A Message Authentication Code (MAC) is a cryptographic checksum that accompanies a message to provide:

1. **Data Integrity**: Verifying that the message content has not been altered during transmission.
2. **Authentication**: Confirming that the message comes from the claimed sender who possesses the secret key.

Unlike digital signatures, MACs use the same secret key for both generating and verifying the code, making them symmetric cryptographic primitives. The general model works as follows:

- The sender computes MAC = f(key, message) and sends both the message and MAC to the recipient.
- The recipient, who knows the same key, can independently compute f(key, message) and verify it matches the received MAC.
- Without knowledge of the key, an attacker should not be able to generate a valid MAC for any message, even after observing multiple valid message-MAC pairs.

## Length Extension Attacks on Hash Functions

Many hash functions (including MD5, SHA-1, and SHA-2 family except SHA-256/224) are vulnerable to length extension attacks due to their use of the Merkle–Damgård construction. This construction processes data in fixed-size blocks and maintains an internal state between blocks.

### How Merkle–Damgård Hashing Works:

1. The input message is padded to align with the block size.
2. An initial value (IV) is established as the starting internal state.
3. The hash function processes each block, updating the internal state with each iteration.
4. The final internal state becomes the hash output.

### The Vulnerability:

In a length extension attack:

1. The attacker knows H(message) but not necessarily the message itself.
2. The attacker can compute H(message || padding || extension) without knowing the original message, as long as they know the:
   - Hash of the original message
   - Length of the original message
   - Data they want to append

This works because the internal state after processing the original message becomes the "initial value" for processing the extension.

## Why MAC = hash(secret || message) is Insecure

The naive MAC construction of `hash(secret || message)` is vulnerable to length extension attacks because:

1. Once an attacker observes a valid (message, MAC) pair, they know `hash(secret || message)`.
2. This hash represents the internal state of the hash function after processing `secret || message`.
3. The attacker can treat this state as the "intermediate hash" and extend the message:
   - They don't need to know the secret
   - They can compute a valid MAC for `secret || message || padding || extension`

This allows an attacker to forge valid MACs for messages they've never seen before, without knowing the secret key, as long as the new message starts with a message for which they've observed a valid MAC.

### Practical Example:

If a server uses `MAC = hash(secret || message)` for authentication:

1. An attacker observes a valid transaction: `message = "amount=100&to=alice"` with its MAC.
2. Using a length extension attack, they can forge a valid MAC for `"amount=100&to=alice&admin=true"` without knowing the secret.
3. This could allow them to execute privileged operations by appending `&admin=true` to a valid transaction.

This vulnerability fundamentally breaks the security properties required of a MAC, as it allows message forgery without knowledge of the secret key.

## Secure MAC Alternatives

To mitigate length extension attacks, several secure MAC constructions exist:

1. **HMAC (Hash-based Message Authentication Code)**:
   - Formula: `HMAC(K, m) = hash((K' ⊕ opad) || hash((K' ⊕ ipad) || m))`, where K' is derived from K
   - Security: Proven secure under the assumption that the underlying hash function is a pseudorandom function
   - Standardized in RFC 2104 and FIPS 198
   - Works with any iterative hash function (including MD5, SHA-1, SHA-2 family)
   - Most widely implemented and deployed MAC algorithm

2. **KMAC (Keccak Message Authentication Code)**:
   - Based on the SHA-3 family (Keccak), which uses the sponge construction instead of Merkle–Damgård
   - Inherently resistant to length extension attacks due to the sponge construction
   - Standardized in NIST SP 800-185
   - Provides better security guarantees than HMAC when used with SHA-3
   - Allows for variable output length

3. **Encrypt-then-MAC**:
   - A composition approach where: `C = Encrypt(K1, message)` and `tag = MAC(K2, C)`
   - Uses separate keys for encryption and authentication
   - Provides both confidentiality and integrity
   - Prevents attacks against the ciphertext
   - Used in secure protocols like TLS 1.2

4. **CMAC (Cipher-based Message Authentication Code)**:
   - Uses a block cipher (like AES) in a CBC-like mode
   - Standardized in NIST SP 800-38B
   - Avoids length extension attacks by design
   - Particularly useful in constrained environments where only block cipher implementations are available

In our demonstration and mitigation, we'll focus on HMAC as the most widely adopted secure MAC algorithm. HMAC has withstood extensive cryptanalysis, is supported in virtually all cryptographic libraries, and provides strong security guarantees when used with modern hash functions like SHA-256.