import base64

data = """begin 755 FLGPRNTR.COM
MOAP!@#PD=`:`-"I&Z_6Z'`&T"<TAP[1,,,#-(4A)7DQ1;AM.=5,:7W5_61EU
;:T1U&4=?1AY>&EAU95AU3AE)&D=:&T9O6%<D
`
end
"""

lines = []
recording = False
for line in data.splitlines():
    if line.startswith("begin "):
        recording = True
        continue
    if line.startswith("end"):
        break
    if recording:
        lines.append(line.strip())

def uudecode_line(line):
    if not line:
        return b''
    length = (ord(line[0]) - 32) & 0x3F
    line = line[1:]
    out = bytearray()
    while line:
        chunk, line = line[:4], line[4:]
        nums = [(ord(c) - 32) & 0x3F for c in chunk]
        a, b, c, d = nums + [0] * (4 - len(nums))
        out.extend([
            (a << 2 | b >> 4) & 0xFF,
            (b << 4 | c >> 2) & 0xFF,
            (c << 6 | d) & 0xFF
        ])
    return bytes(out[:length])

decoded = b''.join(uudecode_line(l) for l in lines if l and not l.startswith('`'))

with open("FLGPRNTR.COM", "wb") as f:
    f.write(decoded)
