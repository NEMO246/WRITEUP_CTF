import subprocess
import struct
import zlib
import re
import os

IMAGE_FILE = 'recovery.img'
PARTITION_OFFSET = 32768
TARGET_FILENAME = 'secret_is_here.png'
OUTPUT_FILENAME = 'FINAL_SECRET.png'

# Presumed image dimensions (calculated in previous steps)
IMG_WIDTH = 1010
IMG_HEIGHT = 152

def find_file_inode(image_path, offset, filename):
    """Finds the file’s inode using 'fls'."""
    print(f"[+] Searching for file '{filename}' in the image...")
    command = ['fls', '-o', str(offset), '-r', image_path]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("[!] ERROR: The 'fls' command was not found. Please install The Sleuth Kit.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR running fls: {e.stderr}")
        return None

    for line in result.stdout.splitlines():
        if filename in line:
            # Find inode at the beginning of the line (e.g., '42-128-3:')
            match = re.search(r'(\d+)-\d+-\d+:', line)
            if match:
                inode = match.group(1)
                print(f"[+] Success! Inode for '{filename}' found: {inode}")
                return inode
    
    print(f"[!] ERROR: File '{filename}' not found in the image.")
    return None

def extract_file_data(image_path, offset, inode):
    """Extracts the raw file data using 'icat'."""
    print(f"[+] Extracting file data with inode {inode}...")
    command = ['icat', '-o', str(offset), image_path, inode]

    try:
        result = subprocess.run(command, capture_output=True, check=True)
        print("[+] File data successfully extracted.")
        return result.stdout
    except FileNotFoundError:
        print("[!] ERROR: The 'icat' command was not found. Please install The Sleuth Kit.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR running icat: {e.stderr}")
        return None

def repair_png(raw_data, width, height):
    """Reconstructs the PNG header and CRC checksum."""
    print("[+] Starting PNG header repair...")

    # Locate the beginning of the first IDAT data block
    try:
        idat_pos = raw_data.index(b'IDAT')
        # We need all data starting from the IDAT block itself
        image_chunks = raw_data[idat_pos - 4:]  # -4 to include the IDAT length field
    except ValueError:
        print("[!] ERROR: IDAT data block not found in extracted file.")
        return None

    # 1. Create the correct 8-byte PNG signature
    png_signature = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'

    # 2. Create IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr_chunk = b'IHDR' + ihdr_data
    
    # 3. Create full IHDR chunk with length and CRC
    full_ihdr_chunk = (
        struct.pack('>I', len(ihdr_data)) +
        ihdr_chunk +
        struct.pack('>I', zlib.crc32(ihdr_chunk))
    )

    # 4. Assemble the final PNG file
    final_png_data = png_signature + full_ihdr_chunk + image_chunks
    print("[+] Header and CRC successfully restored.")
    return final_png_data


def main():
    """Main function to run the entire process."""
    if not os.path.exists(IMAGE_FILE):
        print(f"[!] ERROR: Image file '{IMAGE_FILE}' not found. Make sure it's in the same folder.")
        return

    inode = find_file_inode(IMAGE_FILE, PARTITION_OFFSET, TARGET_FILENAME)
    if not inode:
        return

    raw_data = extract_file_data(IMAGE_FILE, PARTITION_OFFSET, inode)
    if not raw_data:
        return

    repaired_data = repair_png(raw_data, IMG_WIDTH, IMG_HEIGHT)
    if not repaired_data:
        return

    with open(OUTPUT_FILENAME, 'wb') as f:
        f.write(repaired_data)
    
    print("\n========================================================")
    print(f"DONE! The restored file has been saved as '{OUTPUT_FILENAME}'")
    print("========================================================")


if __name__ == '__main__':
    main()
