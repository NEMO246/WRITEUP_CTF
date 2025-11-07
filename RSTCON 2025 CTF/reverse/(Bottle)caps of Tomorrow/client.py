
global debug_enabled  # inserted
import time
import os
import argparse
from pymodbus.client import ModbusTcpClient
debug_enabled = False

def vault_output(temp, flow, rad, alarm, product, ver):
    #os.system('cls' if os.name == 'nt' else 'clear') # <--- LINE REMOVED
        
    print('========================================')
    print(f'  {product} CONTROL UNIT: {ver} ')
    print('========================================')
    print(f' Reactor Core Temp   : {temp} °C')
    print(f' Coolant Flow Rate   : {flow} L/s')
    print(f' Radiation Level     : {rad} mSv/hr')
    print(f" Alarm Status        : {('⚠️  DANGER' if alarm else 'OK')}")
    print('========================================')
    print(' Last Update: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S')))
   

def enable_debug(client):
    global debug_enabled  # inserted
    client.write_register(1337, 2989) # <--- Writes a "magic" value
    result = client.read_holding_registers(1338, count=50)  # <--- Reads hidden data
    if not result.isError():
        debug_enabled = True
    if debug_enabled:
        print(result.registers) # <--- Prints the flag

def get_info(client):
    dev_info = client.read_device_information()
    if not dev_info.isError():
        vendor = str(dev_info.information[0], 'ascii')
        prod = str(dev_info.information[1], 'ascii')
        ver = str(dev_info.information[2], 'ascii')
        return (vendor, prod, ver)
    return None

def main(ip, port):
    print('connecting to server...')
    client = ModbusTcpClient(ip, port=port)
    if client.connect():
        enable_debug(client)  # Added to enable debug mode
        try:
            try:
                while True:
                    result = client.read_holding_registers(0, count=4)
                    if not result.isError():
                        temp, flow, rad, alarm = result.registers
                        _, prod, ver = get_info(client)
                        vault_output(temp, flow, rad, alarm, prod, ver)
                    else:  # inserted
                        print('[ERROR] Could not read from Modbus server.')
                    time.sleep(1)
            except KeyboardInterrupt:
                print('Shutting down client...')
        finally:  # inserted
            client.close()
    else:  # inserted
        print('Failed to connect to Vault-Tec Modbus Server.')

def parse_args():
    parser = argparse.ArgumentParser(description='Connect to a MODBUS device')
    parser.add_argument('ip', help='IP address')
    parser.add_argument('-p', '--port', type=int, default=5020, help='Port number (default: 5020)')
    return parser.parse_args()
if __name__ == '__main__':
    args = parse_args()
    ip = args.ip
    port = args.port
    main(ip, port)