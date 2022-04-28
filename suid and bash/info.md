#### use for bash convert :          
                                       1. python -c 'import pty; pty.spawn("/bin/bash")'
                                       2. script -qc /bin/bash /dev/null
                                       
                                       
#### suid searching :
                                       1.find / -user igor -perm -4000 -print 2>/dev/null
                                       
                                       2.find / -user root -perm -4000 -print 2>/dev/null
