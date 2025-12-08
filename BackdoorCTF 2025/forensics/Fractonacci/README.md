## BackdoorCTF 2025 - Fractonacci Write-up

![Title](images/Title.png)

## Step 1: Initial Reconnaissance
We start with a PNG image named `challenge.png`. The description gives us three distinct keywords: **Beautiful**, **Red**, and **Fractonacci**.

First, we analyze the file metadata using `exiftool` to understand how the image was created.

![exiftool](images/1.png)

**Key Observations:**
1.  **Software:** The image was generated using Python's `Matplotlib` library. This implies the pixels are likely mathematically generated rather than a random photo.
2.  **Dimensions:** The image is huge (6000x6000), containing 36 million pixels.
3.  **Hints:** The word **"Red"** strongly suggests the data is hidden in the **Red Color Channel**.

## Step 2: Analyzing the Algorithm
Standard steganography tools like `zsteg` failed to find simple LSB data. We turned to the challenge title: **Fractonacci**.

This is a portmanteau of **Fractal** and **Fibonacci**.
Combining the clues:
1.  We need to look at the **Red Channel**.
2.  We shouldn't read every pixel. instead, we should read pixels at specific indices.
3.  Those indices follow the **Fibonacci Sequence** ($F_n = F_{n-1} + F_{n-2}$).

*Hypothesis: The flag characters are stored in the Red channel values at indices 0, 1, 1, 2, 3, 5, 8, etc.*

## Step 3: The Solution Script

We wrote a Python script to extract the Red channel data and reconstruct the string based on Fibonacci indices.

**Crucial Detail:** In programming, arrays are 0-indexed. The standard Fibonacci sequence often starts `1, 1`, but to catch the very first character of the flag, we must generate indices starting from `0, 1`.

```python
# solve.py
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
```

## Step 4: Results

Running the script extracts the characters hidden at the calculated coordinates.

![Script Output](images/2.png)

### Flag
`flag{n3wt0n_fr4c74l5_4r3_b34u71ful}`