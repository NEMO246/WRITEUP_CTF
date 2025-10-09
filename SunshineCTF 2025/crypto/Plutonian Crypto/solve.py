import socket
import binascii

def xor(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])

HOST = "chal.sunshinectf.games"
PORT = 25403
BLOCK_SIZE = 16

KNOWN_PLAINTEXT = b"Greetings, Earthlings."
KNOWN_PLAINTEXT_BLOCK_0 = KNOWN_PLAINTEXT[:BLOCK_SIZE]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    for _ in range(16):
        s.recv(1024)

    ciphertexts = []
    try:
        while len(ciphertexts) < 200:
            line = s.recv(4096).strip()
            if not line:
                break
            parts = line.split(b'\n')
            for part in parts:
                if part:
                    ciphertexts.append(binascii.unhexlify(part))
    except Exception as e:
        print(f"Error receiving data: {e}")

msg_len = len(ciphertexts[0])
num_blocks = (msg_len + BLOCK_SIZE - 1) // BLOCK_SIZE

print(f"Message length: {msg_len} bytes ({num_blocks} blocks)")
print(f"Collected {len(ciphertexts)} ciphertexts.")

if len(ciphertexts) < num_blocks:
    print("Not enough ciphertexts to fully recover the key!")
    exit()

keystream_blocks = []
for i in range(num_blocks):
    ct_i_block_0 = ciphertexts[i][:BLOCK_SIZE]
    ks_block = xor(ct_i_block_0, KNOWN_PLAINTEXT_BLOCK_0)
    keystream_blocks.append(ks_block)

full_keystream = b"".join(keystream_blocks)

decrypted_message = xor(ciphertexts[0], full_keystream)

print("\n--- Decrypted message ---\n")
print(decrypted_message.decode('utf-8', 'replace'))
