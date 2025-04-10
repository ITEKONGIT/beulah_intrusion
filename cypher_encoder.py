from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sys

def encrypt_payload(input_file, output_file):
    # Generate random key and IV
    key = get_random_bytes(16)  # 16-byte key
    iv = get_random_bytes(16)   # 16-byte IV

    # Read payload from input file
    try:
        with open(input_file, "rb") as f:
            payload = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    # Encrypt payload
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_payload = cipher.encrypt(pad(payload, AES.block_size))

    # Save key, IV, and encrypted payload to output file
    with open(output_file, "wb") as f:
        f.write(key + iv + encrypted_payload)

    # Output key and IV (for reference)
    print(f"Payload encrypted and saved to '{output_file}'.")
    print("Key:", key.hex())
    print("IV:", iv.hex())

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt_payload.py <input_file> <output_file>")
        print("Example: python encrypt_payload.py payload.bin payload.enc")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        encrypt_payload(input_file, output_file)