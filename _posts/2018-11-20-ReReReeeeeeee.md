---
layout: post
title: "ReReReeeeeeee"
date: 2018-11-19
excerpt: "让我们来一起学$湖湘杯$的参赛选手叫，一起"
tags: [RE]
feature: https://upload.wikimedia.org/wikipedia/commons/thumb/a/a4/AES-SubBytes.svg/1200px-AES-SubBytes.svg.png
comments: true
---

# ReReReeeeeeee


$从湖湘杯说起$

让我们来一起学$湖湘杯$的参赛选手叫，一起：

![](https://github.com/RhythmMark/hello-world/blob/master/pictures/hx1.png?raw=true)
![](https://github.com/RhythmMark/hello-world/blob/master/pictures/hx2.png?raw=true)
![](https://github.com/RhythmMark/hello-world/blob/master/pictures/hx3.png?raw=true)
![](https://github.com/RhythmMark/hello-world/blob/master/pictures/hx4.png?raw=true)

下面是某道密（ni）码（xiang）题的WP

## Crypto 200

**题目**翻译成python如下：

```python
from Crypto.Cipher import AES

key = '1b2e3546586e72869ba7b5c8d9efff0c'.decode('hex')

cipher = AES.new(key, AES.MODE_ECB)

en_flag = '8aeb45c62003ba52e46c9600b3699b8c30386334623434393136633963356136'

(cipher.encrypt(flag[0:16]) + flag[16:]).encode('hex')= en_flag

#求flag
```

**AES部分**可以使用:PEID的Krypto ANALyzer插件

可以看到在``.rdata:000000014001AC50``有AES的S盒：

``63h, 7Ch, 77h, 7Bh, 0F2h, 6Bh, 6Fh, 0C5h, 30h, 1, 67h ……``

该部分的数据被``sub_1400012A0((unsigned __int8 *)&Buf, (__int64)&String1);``调用，所以显然sub_1400012A0是AES加密

其中的Buf是用户的输入，Sting1是秘钥key

进入``sub_140001000``函数可以轻易看到秘钥存放在``.data:000000014001DA40``处

但是经过动态调试可以发现，该函数只会对buf中的**前16bytes**进行aes加密，后面的不变。

---

然后是**hex部分**

ida伪代码：

```cpp
  v4 = &Buf;
  v5 = 32i64;
  v6 = &String1;
  do
  {
    sub_140001550((__int64)v6, (__int64)"%.2x", *(unsigned __int8 *)v4, v3);
    //sprintf(Sting1,"%.2x",Buf);
    v6 += 2;
    v4 = (__int64 *)((char *)v4 + 1);
    --v5;
  }
  while ( v5 );

```

**%.2x**那么明显，所以为什么不能一眼看出来是**sprintf**呢，为什么呢，为什么呢

*C 库函数 int sprintf(char *str, const char *format, ...) ：发送格式化输出到 str 所指向的字符串。*
*C 库函数 int vsprintf(char *str, const char *format, va_list arg)： 使用参数列表发送格式化输出到字符串。*

更何况，``sub_140001550``点进去是这样的

```
__int64 __fastcall sub_140001550(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v4; // rbx
  _BYTE *v5; // rdi
  _QWORD *v6; // rax
  __int64 result; // rax
  __int64 v8; // [rsp+60h] [rbp+18h]
  __int64 v9; // [rsp+68h] [rbp+20h]

  v8 = a3;
  v9 = a4;
  v4 = a2;
  v5 = (_BYTE *)a1;
  v6 = (_QWORD *)sub_1400014E0();
  result = _stdio_common_vsprintf((struct __crt_locale_pointers *)(*v6 | 1i64), v5, 0xFFFFFFFFFFFFFFFFui64, v4, 0i64);
  if ( (signed int)result < 0 )
    result = 0xFFFFFFFFi64;
  return result;
}
```

~~我不知道怎么回事一开始就把_stdio_common_vsprintf的函数名改了然后在里面逆了一整天，美滋滋~~


所以上面的while循环是把Buf里的内容（32Bytes）赋值给String1，其中Buf里的就是``AES(flag[0:16],key) + flag[16:]``

最后是

```
  if ( lstrcmpA(&String1, "8aeb45c62003ba52e46c9600b3699b8c30386334623434393136633963356136") )
    exit(0);
  sub_1400014F0("successful!\nplease entry any key exit...", v7, v8);
```
所以``AES(flag[0:16],key) + flag[16:]``跟它给的字符串一致就是flag了

解题代码还要吗：

```python
from Crypto.Cipher import AES

key = '1b2e3546586e72869ba7b5c8d9efff0c'.decode('hex')

cipher = AES.new(key, AES.MODE_ECB)

en_flag = '8aeb45c62003ba52e46c9600b3699b8c30386334623434393136633963356136'
#这个每题都不同的好像

print cipher.decrypt(en_flag.decode('hex'))[0:16] + en_flag.decode('hex')[16:]
```
---
### Tips

**tips1**：IDA反汇编的结果，不但参数可能不对，``参数数量``也可能不对

如：

``sub_140001550((__int64)v6, (__int64)"%.2x", *(unsigned __int8 *)v4, v3);``

汇编代码是：

```cpp
.text:0000000140001660 loc_140001660:                          ; CODE XREF: main+CF↓j
.text:0000000140001660                 movzx   r8d, byte ptr [rdi]
.text:0000000140001664                 lea     rdx, a2x        ; "%.2x"
.text:000000014000166B                 mov     rcx, rbx        ; __int64
.text:000000014000166E                 call    sub_140001550
```
所以其实只有三个参数


**tips2**：windows平台下的动态调试，32位的可以用``ollydbg``，64位可以用``x64dbg``

**tips3**：对于整数和指针类型参数, x64使用6个寄存器传递前6个参数：edi,rsi,rdx,rcx,r8,r9。从第七个开始通过栈传递。[说得不对的话找这里](https://www.jianshu.com/p/5a4f2d78cb53)

---
进入正题

# re现阶段总结


## 函数和算法

### strlen

**0x80808080**

**0x01010101**

参考：

https://github.com/lattera/glibc/blob/master/string/strlen.c

http://www.stdlib.net/~colmmacc/strlen.c.html

https://stackoverflow.com/questions/20021066/how-the-glibc-strlen-implementation-works

---

### AES

可参考：$S-BOX$

**0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F**（encode）

或

**0x52,0x09,0x6A,0xD5,0x30,0x36**（decode）


参考：

https://github.com/B-Con/crypto-algorithms/blob/master/aes.c

---

### DES 

**14,  4,  13,  1,   2, 15,  11,  8**
或
**'0xe', '0x4', '0xd', '0x1', '0x2', '0xf', '0xb', '0x8'**

参考：

https://github.com/B-Con/crypto-algorithms/blob/master/des.c

### Base64

密文字符集：``ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/``

**等于号**,即``61``，``0x3D``，或者**加号**，即``43``或``0x2B``


更多的可以参考：

https://github.com/B-Con/crypto-algorithms


---

## 工具

### 编译和反编译

```python
>>> from pwn import *
>>> a = 'add ebx,2'
>>> b = asm(a)
>>> b
'\x83\xc3\x02'
>>> c = disasm(b)
>>> c
'   0:   83 c3 02                add    ebx,0x2'

```

网址：

http://shell-storm.org/online/Online-Assembler-and-Disassembler/



----

### 加密算法

PEID的Krypto ANALyzer插件

*至少AES和Base64可以鉴别出来*

---


最后

之前博客的图片都看不到了，因为我上传图片的网站好像出事了还是怎样的……







