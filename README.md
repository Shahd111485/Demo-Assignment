# Message Authentication Code (MAC) Forgery Attack Demonstration

This project demonstrates a practical length extension attack against an insecure MAC implementation and shows how to properly mitigate it using HMAC.

## Project Structure

- `server.py`: Vulnerable server implementation using naive hash-based MAC
- `client.py`: Attack script demonstrating the length extension attack
- `secure_server.py`: Secure implementation using HMAC
- `background_writeup.md`: Explanation of MACs and length extension attacks
- `mitigation_writeup.md`: Detailed explanation of HMAC and why it mitigates the attack

## Setup Instructions

No external dependencies are required. The implementation uses only Python's built-in libraries:
- `hashlib` for cryptographic functions
- `struct` for binary data manipulation
- `binascii` for hexadecimal conversions

2. Clone this repository:
   ```bash
   git clone [repository-url]
   cd mac-forgery-demonstration
   ```

## Running the Demonstration

### Step 1: Run the vulnerable server
```bash
python server.py
```
Note down the MAC value printed in the output (e.g., e79bc808a179bbb5dbcd346020a3c048).

### Step 2: Perform the attack
```bash
python client.py
```
When prompted, enter the MAC value from Step 1.

The client will demonstrate a length extension attack, forging a valid MAC for a modified message without knowing the secret key.

### Step 3: Test the secure implementation
```bash
python secure_server.py
```
When prompted, enter the forged MAC from Step 2 to verify that the attack no longer works.

## Understanding the Attack

This demonstration shows a length extension attack against the insecure MAC construction:
```python
MAC = hash(secret || message)
```

Our implementation correctly uses the SECRET_KEY length (64 bytes) to calculate the proper padding and successfully forge a valid MAC for the extended message.

The attack exploits the internal structure of Merkle–Damgård hash functions like MD5 and SHA-1, allowing an attacker to:
1. Observe a valid (message, MAC) pair
2. Generate a valid MAC for `message || padding || extension` without knowing the secret

In our example, we start with a legitimate message:
```
amount=100&to=alice
```

And extend it to add admin privileges:
```
amount=100&to=alice[padding bytes]&admin=true
```

## Mitigation Strategy

The secure implementation uses HMAC instead:
```python
MAC = HMAC(key, message)
```

HMAC is specifically designed to prevent length extension attacks through its nested hash structure:
```
HMAC(K, m) = hash((K' ⊕ opad) || hash((K' ⊕ ipad) || m))
```

Additional security improvements include:
- Using SHA-256 instead of MD5
- Implementing constant-time comparison
- Better code structure and documentation

## Further Reading

- See `background_writeup.md` for a detailed explanation of MACs and length extension attacks
- See `mitigation_writeup.md` for details on how HMAC mitigates these attacks
- [HMAC: Keyed-Hashing for Message Authentication (RFC 2104)](https://tools.ietf.org/html/rfc2104)
- [Length Extension Attacks Explained](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

## Contributors

This project was created as part of the Data Integrity and Authentication course assignment.

## License

[MIT License](LICENSE)