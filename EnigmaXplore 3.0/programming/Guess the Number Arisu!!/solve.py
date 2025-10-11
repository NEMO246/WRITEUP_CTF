from pwn import *

HOST = '0.cloud.chals.io'
PORT = 15985

def make_query(r, numbers):
    """Sends an OR query with a list of numbers and returns the result."""
    r.sendlineafter(b'Enter your choice: ', b'1')
    r.sendlineafter(b'Enter operation type (1 for AND, 2 for OR): ', b'2')
    r.recvuntil(b'Enter up to 200 unique numbers (end with -1):\n')
    for num in numbers:
        r.sendline(str(num).encode())
    r.sendline(b'-1')
    r.recvuntil(b'Result: ')
    return int(r.recvline().strip().decode())

# Connect and select the game
r = remote(HOST, PORT)
r.sendlineafter(b'Enter your choice: ', b'0')

# Step 1: Determine the upper 8 bits
log.info("Query 1: Determining the upper 8 bits...")
numbers1 = [i for i in range(200)]
result1 = make_query(r, numbers1)
upper_bits = result1 & 0xFF00

# Step 2: Determine the lower 8 bits
log.info("Query 2: Determining the lower 8 bits...")
numbers2 = [i * 256 for i in range(200)]
result2 = make_query(r, numbers2)
lower_bits = result2 & 0x00FF

# Step 3: Assemble the number and send the answer
secret_number = upper_bits | lower_bits
log.success(f"Final number: {secret_number}")
r.sendlineafter(b'Enter your choice: ', b'2')
r.sendlineafter(b'Enter your guess: ', str(secret_number).encode())

# Get the flag
r.interactive()