import sys

def decompress(input_file, output_file):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except:
        print(f"File {input_file} not found")
        return

    out_buffer = bytearray()

    # Process the file in 2-byte chunks (Token, Literal)
    for i in range(0, len(data), 2):
        if i + 1 >= len(data): break
            
        token = data[i]
        literal = data[i+1]

        # Reverse the bit-packing logic found in assembly:
        # Token >> 3  -> Top 5 bits = Offset
        # Token & 7   -> Bottom 3 bits = Length
        offset = token >> 3
        length = token & 0b111

        # Step 1: Recover compressed data from history
        if length > 0:
            start_index = len(out_buffer) - offset
            for _ in range(length):
                if start_index < len(out_buffer):
                    out_buffer.append(out_buffer[start_index])
                    start_index += 1
                else:
                    out_buffer.append(0)

        # Step 2: Always append the literal byte
        out_buffer.append(literal)

    # Save to file
    with open(output_file, 'wb') as f:
        f.write(out_buffer)
    print(f"Result saved to {output_file}\n")

    # Print to console
    print("Recovered Output:\n")
    print(out_buffer.decode('utf-8', errors='ignore'))

if __name__ == "__main__":
    decompress("flag.fshr", "flag_decoded.txt")