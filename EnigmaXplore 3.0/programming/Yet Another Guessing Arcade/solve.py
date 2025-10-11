TARGET = 3132047116690661900

def popcount(n):
  """Counts the number of set bits in an integer."""
  return bin(n).count('1')

# Iterate through all possible bit counts (p)
for p in range(65):
  # Calculate the key K = 2^p - 1.
  # (1 << p) is a fast way to compute 2^p.
  key = (1 << p) - 1
  
  # Find the potential input X
  potential_input = TARGET ^ key
  
  # Check if the popcount of our candidate matches p
  if popcount(potential_input) == p:
    print(f"[+] Found!")
    print(f"    Bit count (p): {p}")
    print(f"    Key (K): {key}")
    print(f"    Correct Input (X): {potential_input}")
    # Exit the loop after finding the solution
    break