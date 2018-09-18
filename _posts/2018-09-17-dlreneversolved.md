---
layout: post
title: "ret2dlresolve还没做出来，陷入沉思.jpg"
date: 2018-09-17
excerpt: "（我没想到会有人看我的blog+彩蛋有我最喜欢的python"
tags: [dlresolve,__file__,os.path]
feature: http://bpic.588ku.com/element_origin_min_pic/16/11/03/a2764458a6fc972bd84a63391aab47ae.jpg
comments: true
---

~~困得神志不清， 全靠求生意志死撑~~
我决定先跟着[Return-to-dl-resolve](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)的思路走一遍

类型为``PT_DYNAMIC``的``段``包含了``.dynamic``节，该段保存了一个由类型为``Elf32_Dyn``的结构体组成的数组，``Elf32_Dyn``的结构如下：

```
typedef struct {
    Elf32_Sword d_tag;
    union {
        Elf32_Word d_val;
        Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
```

一些d_tag在这里：

https://docs.oracle.com/cd/E19957-01/806-0641/chapter6-42444/index.html


例如在我手头上的程序里，它长这样
![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/1.png)
里面有很多熟悉的类型，在上一篇blog提到过的。

动态段在哪可以通过命令readelf查到
![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/2.png)


前面的东西都很乱，以read等为例。

能看到，动态段里有一项
``LOAD:08049F94                 Elf32_Dyn <17h, <80482B0h>> ; DT_JMPREL``
其中``0x17``是``d_tag``，指DT_JMPREL，决定了：
80482B0h是``Relocation Table``的起始地址。我们可以看看这个表都有啥：
![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/3.png)

该表中有几个``Elf32_Rel``，其结构如下：
```
typedef struct {
    Elf32_Addr r_offset;    
    Elf32_Word r_info;      
} Elf32_Rel;
```
可以配合gdb服用：
![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/4.png)
前面的是r_offset，是重定位入口的偏移，我们可以看到，

所以read的offset是0x804A0C，alarm的是0x804A10，__libc_start_main的是0x804A14，和.got.plt节中显示的相对应——

![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/5.png)


之前提到过
GOT是全局偏移表，分.got和``.got.plt``两部分
前者用于保存全局变量引用位置，后者用于``保存函数引用位置``。


---
彩蛋

.got.plt里面的地址，在该函数未使用之前指向.plt里的地址，在该函数再次使用后直接指向该函数。

---


而r_info的低8位表示重定位入口的类型，高24位表示重定位入口的符号在符号表中的下标。

如图，三个函数的重定位类型都为0x07，对应R_386_JUMP_SLOT，下标分别是1，2，4。

至于为什么没有3，因为3给在.got节里的的``__imp___gmon_start__``了吖

这个可以直接看符号表验证

![Alt text](https://raw.githubusercontent.com/RhythmMark/hello-world/master/pictures/6.png)


在使用dlresolve之前，还需要知道_dl_runtime_resolve(link_map, reloc_arg)里调用的``_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)``的一些细节——

在_dl_fixup里，首先会使用第二个参数计算重定位的入口：

``const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);``

简化一下就是

``reloc = D_PTR (l, l_info[DT_JMPREL] + reloc_offset)``

这里的JMPREL即.rel.plt，reloc_offset即reloc_arg

.rel.plt长这样：

```
LOAD:080482B0 ; ELF JMPREL Relocation Table
LOAD:080482B0                 Elf32_Rel <804A00Ch, 107h> ; R_386_JMP_SLOT read
LOAD:080482B8                 Elf32_Rel <804A010h, 207h> ; R_386_JMP_SLOT alarm
LOAD:080482C0                 Elf32_Rel <804A014h, 407h> ; R_386_JMP_SLOT __libc_start_main
LOAD:080482C0 LOAD            ends
```

所以reloc就是上表中的对应函数的条目

然后会根据``r -> r_info``来找到``.dynsym``中对应的条目——

``const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];``

``.dynsym``长这样：
```
LOAD:080481CC                 Elf32_Sym <0>
LOAD:080481DC                 Elf32_Sym <offset aRead - offset byte_804822C, 0, 0, 12h, 0, 0> ; "read"
LOAD:080481EC                 Elf32_Sym <offset aAlarm - offset byte_804822C, 0, 0, 12h, 0, 0> ; "alarm"
LOAD:080481FC                 Elf32_Sym <offset aGmonStart - offset byte_804822C, 0, 0, 20h, 0, 0> ; "__gmon_start__"
LOAD:0804820C                 Elf32_Sym <offset aLibcStartMain - offset byte_804822C, 0, 0, 12h, 0, \ ; "__libc_start_main"
LOAD:0804820C                            0>
LOAD:0804821C                 Elf32_Sym <offset aIoStdinUsed - offset byte_804822C, \ ; "_IO_stdin_used"
LOAD:0804821C                            offset _IO_stdin_used, 4, 11h, 0, 10h>
```

还会检查reloc->r_info的最低位是不是R_386_JUMP_SLOT=7
（Sanity check that we're really looking at a PLT relocation）
   
 ``assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);``


 接着通过strtab+sym->st_name找到符号表字符串，result为libc基地址

``result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope, version, ELF_RTYPE_CLASS_PLT, flags, NULL);``

``.dynstr``长这样：

```
LOAD:0804822C byte_804822C    db 0                    ; DATA XREF: LOAD:080481DC↑o
LOAD:0804822C                                         ; LOAD:080481EC↑o ...
LOAD:0804822D aLibcSo6        db 'libc.so.6',0
LOAD:08048237 aIoStdinUsed    db '_IO_stdin_used',0   ; DATA XREF: LOAD:0804821C↑o
LOAD:08048246 aRead           db 'read',0             ; DATA XREF: LOAD:080481DC↑o
LOAD:0804824B aAlarm          db 'alarm',0            ; DATA XREF: LOAD:080481EC↑o
LOAD:08048251 aLibcStartMain  db '__libc_start_main',0
LOAD:08048251                                         ; DATA XREF: LOAD:0804820C↑o
LOAD:08048263 aGmonStart      db '__gmon_start__',0   ; DATA XREF: LOAD:080481FC↑o
LOAD:08048272 aGlibc20        db 'GLIBC_2.0',0
LOAD:0804827C                 dd 20000h, 2, 10002h, 10001h, 1, 10h, 0
LOAD:08048298                 dd 0D696910h, 20000h, 46h, 0
```


得到value为libc基址加上要解析函数的偏移地址，也即实际地址

``value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);``
    
  最后把value写入相应的GOT表条目中
    
   `` return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);``




###看例题：

####stage1 

payload1 -> 

``padding + read_plt + ppp_ret + 0(stdin) + base_stage(addr) + 100(len) + pop_ebp_ret(ebp = base_stage) + base_stage_addr + leave_ret(esp = base_stage)``
旨在往``base_stage``读入100个字符，并让``esp``指向位于``bss``段的``base_stage``

payload2->

//注意此时esp已经指向bae_stage了，也就是栈已经跑到bss段上了

``’AAAA’(ebp) + write_plt_addr + 'AAAA' + 1(stdout) + base_stage_add_80(addr) + len(cmd) + padding + cmd + '\x00' + padding``

执行write，输出'/bin/sh'

####stage2

stage1中payload2的``write_plt``换成了``plt_0 + write_index_offset``

``write_plt``:可以认为直接执行write（因为之前用过）

``plt_0 + write_index``：执行_dl_runtime_resolve(link_map_addr, write_index_offset)

此时在_dl_fixup流程中，
```
   i) // 首先通过参数reloc_arg计算重定位入口，这里的JMPREL即.rel.plt，reloc_offset即reloc_arg
    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  ii) // 然后通过reloc->r_info找到.dynsym中对应的条目
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  iii)  // 这里还会检查reloc->r_info的最低位是不是R_386_JUMP_SLOT=7
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

……
```
第``i)``里的``reloc_offset``能被我们控制，也就是``ii)``中的reloc我们可以伪造，这就是stage3里面要做的。

PS：这里的所谓index是该函数的Elf32_Rel（r_offset+r_info）到.rel.plt的偏移

####stage3:

把stage2里payload2中，倒数第二个padding里填了个``fake_reloc``

这里的fake_reloc和真正的reloc没什么区别，好吧，没区别，就所在地址不同，内容一样的。脚本里，“执行write”时用到了这个fake_reloc

####stage4：

这次伪造了一个``fake_sym``，即于payload2中的倒数第二个padding增加了``'B' * align + fake_sym``，并把``fake_reloc``的``r_info``改成了``(index_dynsym << 8) | 0x7``，即脚本运行中

```
   i) // 首先通过参数reloc_arg计算重定位入口，这里的JMPREL即.rel.plt，reloc_offset即reloc_arg
    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  ii) // 然后通过reloc->r_info找到.dynsym中对应的条目
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  iii)  // 这里还会检查reloc->r_info的最低位是不是R_386_JUMP_SLOT=7
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

……
```
``ii）``那里得到的是我们的fake_sym


其中

``fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)``

PS:

```
struct Elf32_Sym
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
……
};
```

例如，0x080481DC是read的项，在gdb可以看到：

```
0x80481dc:	0x1a	0x00	0x00	0x00  | 0x00  0x00  0x00   0x00
……
```
可见，read的名字的字符串与``.dynstr``起始地址的相对位移为0x1a

而``align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)``

这里的对齐操作是因为dynsym里的Elf32_Sym结构体都是0x10字节大小

所以当以.dynsym为起点查找的话只能+0x10，+0x10这样子

所以要保证fake_sym_addr能通过.dynsym的地址+0x10，+0x10达到这样子

``index_dynsym = (fake_sym_addr - dynsym) / 0x10``

####stage5

刚刚伪造的``fake_sym``的st_name指的还是字符表中的位置，这次指向我们伪造的字符串。

payload2中，st_name 由``0x4c``换成了`` (fake_sym_addr + 0x10) - dynstr``

把read的参数
```
payload2 += p32(1)
payload2 += p32(base_stage + 80)
payload2 += p32(len(cmd))
```
换成
```
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
```
两行'aaaa'是为后面fake_reloc等对于base_stage的相对偏移不变。


---
lev12->下篇见




---
关于系统调用[read](http://man7.org/linux/man-pages/man2/read.2.html)
的一些tips：

1.读入'\n'即0x0a的，
2.如果连续两次调用sys_read，第一次因为长度不够没读完的东西会留到下一次成为下一次读入内容的前缀






---
彩蛋：

get到一个用objdump查找某个section的方法

``objdump -s -j .plt bof``


---
彩蛋：
出现
```
root@kali:~/Desktop/king/12lev# gcc -o bof -m32 -fno-stack-protector bof.c
In file included from /usr/include/unistd.h:25:0,
                 from bof.c:1:
/usr/include/features.h:424:12: fatal error: sys/cdefs.h: No such file or directory
 #  include <sys/cdefs.h>
            ^~~~~~~~~~~~~
compilation terminated.
root@kali:~/Desktop/king/12lev# vim bof.c
root@kali:~/Desktop/king/12lev# vim bof.c
root@kali:~/Desktop/king/12lev# gcc -o bof -m32 -fno-stack-protector bof.c
In file included from bof.c:1:0:
/usr/include/stdio.h:27:10: fatal error: bits/libc-header-start.h: No such file or directory
 #include <bits/libc-header-start.h>
          ^~~~~~~~~~~~~~~~~~~~~~~~~~
compilation terminated.
root@kali:~/Desktop/king/12lev# vim bof.c
```
的解决方法：

``sudo apt-get install g++-multilib``



---
继续彩蛋

python装饰器

参考：

https://foofish.net/python-decorator.html

>让其他函数或类在不需要做任何代码修改的前提下增加额外功能

> @符号是装饰器的语法糖，它放在函数开始定义的地方（def foo():上一行+@use_logging），这样就可以省略最后一步再次赋值的操作（省去foo = use_logging(foo)）

---

get到了一些没用过的函数

这里有一行代码：
``os.chdir(os.path.dirname(os.path.realpath(__file__)))``
->将工作目录切换到该py文件的当前目录

os.chdir(path):用于改变当前工作目录至path

os.path.dirname(path):返回path的目录，如``/root/Desktop/king/12lev``

os.path.realpath(__file__):脚本所在的绝对路径，如``/root/Desktop/king/12lev/2wrapper.py``

PS：``__file__``

参考：https://www.jianshu.com/p/d114148e72e1

划重点：

如果运行该脚本时使用绝对路径，``__file__``就是脚本的绝对路径。

如果使用的是相对路径，``__file__``就是脚本的相对路径。


再PS：``sys.path``是python的``搜索模块的路径集``，是一个list
~~超乱入~~

---
蛋中蛋：

Python中获取路径``os.getcwd()``和``os.path.dirname(os.path.realpath(__file__))``的区别

参考：

http://www.th7.cn/Program/Python/201709/1240158.shtml

https://blog.csdn.net/cyjs1988/article/details/77839238

划重点：

os.getcwd:获取起始执行目录，即当A调用B，即使``os.getcwd()``在B里，返回的也是A的的目录。

而``os.path.dirname(os.path.realpath(__file__))``返回的是它所在的文件的目录。

---

这里又有一句代码：

``p = subprocess.Popen(name, stdin=subprocess.PIPE, stdout=file('/dev/null','w'), stderr=subprocess.STDOUT)``

python的``subprocess``模块可以参考：

https://docs.python.org/2/library/subprocess.html

https://www.cnblogs.com/Security-Darren/p/4733368.html


>subprocess.Popen 类
通过调用：
``subprocess.Popen(args, bufsize=0, executable=None, stdin=None, stdout=None, stderr=None, preexec_fn=None, close_fds=False, shell=False, cwd=None, env=None, universal_newlines=False, startupinfo=None, creationflags=0)``
　　->创建并返回一个子进程，并在这个进程中执行指定的程序。
参数介绍：
*args*：唯一必须的参数。
为要执行的命令或可执行文件的路径。
一个由字符串组成的序列（通常是列表）。
列表的第一个元素是可执行程序的路径，剩下的是传给这个程序的参数。
*bufsize*：控制 stdin, stdout, stderr 等参数指定的文件的缓冲。
*executable*：如果这个参数不是 None，将替代参数 args 作为可执行程序；
*stdin*：指定子进程的标准输入；
*stdout*：指定子进程的标准输出；
*stderr*：指定子进程的标准错误输出；
对于 stdin, stdout 和 stderr 而言，如果他们是 None（默认情况），那么子进程使用和父进程相同的标准流文件。
父进程如果想要和子进程通过 communicate() 方法通信，对应的参数必须是 subprocess.PIPE
……

然后
``subprocess.PIPE``:为标准流文件打开一个管道
``/dev/null``:或称空设备，是一个特殊的设备文件，它丢弃一切写入其中的数据（但报告写入操作成功），读取它则会立即得到一个EOF。

---
一个关于setbuf的彩蛋

参考：https://blog.csdn.net/sole_cc/article/details/40383033

>缓冲区分为三种类型：全缓冲、行缓冲和不带缓冲。

>1) 全缓冲
在这种情况下，当填满标准I/O缓存后才进行实际I/O操作。全缓冲的典型代表是对磁盘文件的读写。

>2) 行缓冲
在这种情况下，当在输入和输出中遇到换行符时，执行真正的I/O操作。这时，我们输入的字符先存放在缓冲区，等按下回车键换行时才进行实际的I/O操作。典型代表是标准输入(stdin)和标准输出(stdout)。

>3) 不带缓冲
也就是不进行缓冲，标准出错情况stderr是典型代表，这使得出错信息可以直接尽快地显示出来。

>目前主要的缓存特征是：stdin和stdout是行缓存；而stderr是无缓存的。 

>setbuf()和setvbuf()函数的实际意义在于：用户打开一个文件后，可以建立自己的文件缓冲区，而不必使用fopen()函数打开文件时设定的默认缓冲区。这样就可以自己来控制缓冲区。

---
``ld-linux.so``

参考：https://www.systutorials.com/docs/linux/man/8-ld-linux.so/

--library-path PATH

用PATH里的libc库，而不是``LD_LIBRARY_PATH``环境变量里设定的。





---

参考：

1.https://bestwing.me/Return-to-dl-resolve.html

2.http://pwn4.fun/2016/11/09/Return-to-dl-resolve/

3.






----
哔哔几句
1.羡慕逻辑都比我强的普通人类

2.有人问我普通人类都把

2.之前都用的图片上传，然后听说有人看不了图片（所以为什么会有人看我的blog阿），然后这篇开始就直接把截图扔到自己博客这里了……我应该早就这样做的 -0-

3.然后这样我编辑的时候好像又不能及时看了……想了下还是扔自己的服务器上吧……

4.……那我终于有一天缺钱到服务器都养不起了怎么办？

5.最后我突然想起我能放github上（。）

 