---
layout: post
title: "做ret2dlresolve前的准备工作之PLT/GOT/Lazy binding"
date: 2018-09-6
excerpt: "我们终于知道第一次调用read的时候发生了什么"
tags: [pwn,ELF,GOT,PLT,ROP]
feature: https://rafaelchen.files.wordpress.com/2017/09/e89ea2e5b995e5bfabe785a7-2017-09-25-e4b88be58d889-36-07.png?w=1100
comments: true
---

先看下ELF里PT_LOAD类型的存放程序代码的``text``段和存放全局变量和动态链接信息的``data``段，以及动态链接可执行文件特有的、包含了动态连接器所必须的一些信息的动态段(``dynamic segment``)：
```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  ...
  LOAD           0x000000 0x08048000 0x08048000 0x00630 0x00630 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00118 0x0011c RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
```




对应的里面的节(section)：

```
 Section to Segment mapping:
  Segment Sections...
   ...
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss 
   04     .dynamic
   ...
```
<read@plt>内容

```
08048300 <read@plt>:
 8048300:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 8048306:	68 00 00 00 00       	push   $0x0
 804830b:	e9 e0 ff ff ff       	jmp    80482f0 <read@plt-0x10>
```

```
080482f0 <read@plt-0x10>:
 80482f0:	ff 35 04 a0 04 08    	pushl  0x804a004
 80482f6:	ff 25 08 a0 04 08    	jmp    *0x804a008
 80482fc:	00 00                	add    %al,(%eax)

```




直接开始。

#### 调用read@plt

 ``0x804844c:	call   0x8048300 <read@plt>``  ->-.text里

然后
#### 跳到GOT表
 ``0x8048300 <read@plt>:	jmp    DWORD PTR ds:0x804a00c`` 

这里DWORD PTR（Double Word Pointer）是双字节类型（4个字节32位）指针的意思，ds是data segment，数据段的的意思

可以看下0x804a00c具体是什么东西

```
gdb-peda$ xinfo 0x804a00c
0x804a00c --> 0x8048306 (<read@plt+6>:	push   0x0)
Virtual memory mapping:
Start : 0x0804a000
End   : 0x0804b000
Offset: 0xc
Perm  : rw-p
```

0x804a00c是在.got.plt节里的，从ida可以看到
``.got.plt:0804A00C off_804A00C     dd offset read``

---
彩蛋：
```
GOT:
global offset table
全局偏移表
分.got和.got.plt两部分
前者用于保存全局变量引用位置，后者用于保存函数引用位置。
```
由于在这里read是第一次调用，因此这里存储的不是read的真实地址，而是指向了read的PLT跳转表条目，这里其实就是下一行代码。

---

继续彩蛋：

这是.got.plt节里的所有内容：

```
.got.plt:0804A000                 dd offset stru_8049F14
.got.plt:0804A004 dword_804A004   dd 0                    ; DATA XREF: sub_80482F0↑r
.got.plt:0804A008 dword_804A008   dd 0                    ; DATA XREF: sub_80482F0+6↑r
.got.plt:0804A00C off_804A00C     dd offset read          ; DATA XREF: _read↑r
.got.plt:0804A010 off_804A010     dd offset alarm         ; DATA XREF: _alarm↑r
.got.plt:0804A014 off_804A014     dd offset __libc_start_main
.got.plt:0804A014                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0804A014 _got_plt        ends
.got.plt:0804A014
```
---
我们会看到前三项都不是什么函数，它存放了三个偏移量：

``GOT[0]``指向了可执行文件``动态段``的地址，gdb可查出：

``0x804a000 --> 0x8049f14``，正是DYNAMIC segment的地址

``GOT[1]``存放了``link_map``结构的地址，动态连接器利用该地址来对符号进行解析。

可以在link.h里找到它的定义
```
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };
```


``GOT[2]``存放了指向动态连接器``_dl_runtime_resolve()``函数的地址。


跳转到0x804a00c里保存的一个四字节大小的地址0x8048306处，并运行该地址处的指令。

---
彩蛋：

```
jmp addr 
执行addr的内容
```
```
jmp DWORD PTR ds:addr
执行addr里的地址里的内容
```
---

#### 由于是第一次调用，got表存放的是指向plt表里，调用指令对应的地址
进入.plt（包含动态链接器调用从共享库导入的函数所必需的相关代码，其中PLT是Procedure Linkage Table，过程链接表）节
```
0x8048306 <read@plt+6>:	    push   0x0
0x804830b <read@plt+11>:	jmp    0x80482f0
```
#### 该函数在GOT表中条目的偏移入栈
0x0入栈，0x0是因为函数read是got表里面的第一个条目。
index入栈，此时的栈为
```
[------------------------------------stack-------------------------------------]
0000| 0xffffd1c8 --> 0x0 
0004| 0xffffd1cc --> 0x8048451 (add    esp,0x10)
```

---
彩蛋：

第一次调用不同的函数，似乎只有index不同


---

然后跳到0x80482f0，这是.plt节的起始位置，即第一个PLT条目。
```
0x80482f0:	push   DWORD PTR ds:0x804a004
```
#### link_map地址入栈
此时的栈为
```
[------------------------------------stack-------------------------------------]
0000| 0xffffd1c4 --> 0xf7ffd940 --> 0x0 
0004| 0xffffd1c8 --> 0x0 
0008| 0xffffd1cc --> 0x8048451 (add    esp,0x10)
...
```
可以看到把```0xf7ffd940```入栈了，而```0x804a004```其实是``GOT[1]``，也就是说```0xf7ffd940```其实是``link_map``结构的地址




至此``_dl_runtime_resolve``所需的两个参数齐了。

然后
#### 执行_dl_runtime_resolve，将.got.plt节对应的GOT条目替换为函数的地址。
5）
```
0x80482f6:	jmp    DWORD PTR ds:0x804a008
```
其中``0x804a008``其实是``GOT[2]``，也就是说里面存放的是``_dl_runtime_resolve(link_map,index)``函数的地址。


所以开始执行``_dl_runtime_resolve()``函数

```
=> 0xf7fea340:	push   eax
   0xf7fea341:	push   ecx
   0xf7fea342:	push   edx
   0xf7fea343:	mov    edx,DWORD PTR [esp+0x10]
   0xf7fea347:	mov    eax,DWORD PTR [esp+0xc]
   ....
```
我们或许不需要深入地研究这个函数的每一行代码，不过喜欢的话可以参考：

源码：

https://github.com/lattera/glibc/blob/master/sysdeps/i386/dl-trampoline.S

伪代码：

https://www.ibm.com/developerworks/cn/linux/l-elf/part2/index.html

反正，它会在找到read在library的位置后，将它填回到.got.plt。

此后，再有下一次调用read函数的时候，PLT条目会直接跳转到函数本身。

我们可以看看``_dl_runtime_resolve()``函数执行后的GOT表，即调用read@plt时，``call   0x8048300 <read@plt>``后``jmp    DWORD PTR ds:0x804a00c``会跳到的地方。

```
gdb-peda$ xinfo 0x804a00c
0x804a00c --> 0xf7eac130 (<read>:	push   esi)
Virtual memory mapping:
Start : 0x0804a000
End   : 0x0804b000
Offset: 0xc
Perm  : rw-p
Name  : /root/Desktop/king/12lev/level12
gdb-peda$ 
```
可以看到已经从``0x8048306 (<read@plt+6>:	push   0x0)``变成了``0xf7eac130 (<read>:	push   esi)``


参考：

《Linux二进制分析》

https://www.slideshare.net/AngelBoy1/re2dlresolve


这里有几张总结图：

https://blog.csdn.net/linyt/article/details/51893258

