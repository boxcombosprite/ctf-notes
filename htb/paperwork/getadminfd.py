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
