import base64
import os

def create_solver():
    if not os.path.exists("program.wasm"):
        print("[-] program.wasm not found!")
        return

    with open("program.wasm", "rb") as f:
        wasm_b64 = base64.b64encode(f.read()).decode()

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WASM Solver</title>
    <style>body {{ background: #111; color: #0f0; font-family: monospace; padding: 20px; }} input {{ width: 400px; padding: 5px; }}</style>
</head>
<body>
    <h3>WASM Runner</h3>
    <input type="text" id="passInput" value="">
    <button onclick="run()">Check</button>
    <pre id="output"></pre>
    <script>
        const wasmBase64 = "{wasm_b64}";
        const wasmBytes = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
        
        const wasiImports = {{
            wasi_snapshot_preview1: {{
                fd_write: (fd, iovs, iovs_len, nwritten) => {{
                    const mem = new DataView(wasmInstance.exports.memory.buffer);
                    let str = "";
                    for (let i = 0; i < iovs_len; i++) {{
                        const ptr = mem.getUint32(iovs + i * 8, true);
                        const len = mem.getUint32(iovs + i * 8 + 4, true);
                        const chunk = new Uint8Array(wasmInstance.exports.memory.buffer, ptr, len);
                        str += new TextDecoder().decode(chunk);
                    }}
                    document.getElementById("output").innerText += str;
                    return 0;
                }},
                fd_read: (fd, iovs, iovs_len, nread) => {{
                    const mem = new DataView(wasmInstance.exports.memory.buffer);
                    const ptr = mem.getUint32(iovs, true);
                    const encoder = new TextEncoder();
                    const bytes = encoder.encode(currentPass + "\\n");
                    new Uint8Array(wasmInstance.exports.memory.buffer, ptr, bytes.length).set(bytes);
                    mem.setUint32(nread, bytes.length, true);
                    return 0;
                }},
                // Fix: Add random_get implementation
                random_get: (buf, buf_len) => {{
                    const mem = new Uint8Array(wasmInstance.exports.memory.buffer);
                    for (let i = 0; i < buf_len; i++) {{
                        mem[buf + i] = (Math.random() * 256) | 0;
                    }}
                    return 0;
                }},
                poll_oneoff: () => 0,
                proc_exit: () => {{ throw "EXIT"; }},
                clock_time_get: () => 0, environ_sizes_get: () => 0, environ_get: () => 0, args_sizes_get: () => 0, args_get: () => 0, fd_seek: () => 0, fd_close: () => 0, fd_fdstat_get: () => 0
            }}
        }};

        let wasmInstance;
        let currentPass = "";

        async function run() {{
            document.getElementById("output").innerText = "";
            currentPass = document.getElementById("passInput").value;
            try {{
                const module = await WebAssembly.compile(wasmBytes);
                wasmInstance = await WebAssembly.instantiate(module, wasiImports);
                wasmInstance.exports._initialize();
            }} catch (e) {{
                if (e !== "EXIT") console.error(e);
            }}
        }}
    </script>
</body>
</html>
    """
    with open("solve.html", "w") as f: f.write(html_content)
    print("[+] Created solve.html")

if __name__ == "__main__":
    create_solver()