from PIL import Image

def get_fibonacci_indices(max_n):
    indices = [0, 1]
    a, b = 0, 1
    while True:
        nxt = a + b
        if nxt >= max_n:
            break
        indices.append(nxt)
        a, b = b, nxt
    
    # Remove duplicates (1 appears twice) and sort
    return sorted(list(set(indices)))

def solve():
    print("[-] Loading image...")
    try:
        img = Image.open("challenge.png")
    except FileNotFoundError:
        print("Error: challenge.png not found. Make sure it is in the same folder.")
        return

    # Extract the Red channel data
    # (The flag is hidden in the Red values, not Green or Blue)
    r_channel = list(img.split()[0].getdata())
    
    print("[-] Generating Fractonacci sequence...")
    fib_indices = get_fibonacci_indices(len(r_channel))
    
    print("[-] Extracting flag...")
    flag_chars = []
    
    for idx in fib_indices:
        # Convert the pixel Red value (int) to a character (ASCII)
        char = chr(r_channel[idx])
        flag_chars.append(char)
        
        # Stop exactly at the closing curly brace
        if char == '}':
            break
            
    full_flag = "".join(flag_chars)
    
    print(f"\n[+] SUCCESS! Extracted Flag:")
    print("-" * 40)
    print(full_flag)
    print("-" * 40)

if __name__ == "__main__":
    solve()