---
layout: post
title: "强网杯-StreamGame3-Writeup"
date: 2012-05-23
excerpt: "相关攻击了解一下."
tags: [StreamGame3, correlation attack,流密码,Crypto,CTF,Write up强网杯]
feature: http://www.nsoad.com/upload/20161014/d6804a98376fedd714d6e578aa6c7e14.png
comments: true
---

~~Rhythm终于肯填强网杯StreamGame3的坑了~~

----

时隔……一个月，回忆一下题目先

```python
from flag import flag
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag)==24

def lfsr(R,mask):
    output = (R << 1) & 0xffffff
    i=(R&mask)&0xffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)
def single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask):
    (R1_NEW,x1)=lfsr(R1,R1_mask)
    (R2_NEW,x2)=lfsr(R2,R2_mask)
    (R3_NEW,x3)=lfsr(R3,R3_mask)
    return (R1_NEW,R2_NEW,R3_NEW,(x1*x2)^((x2^1)*x3))

R1=int(flag[5:11],16)
R2=int(flag[11:17],16)
R3=int(flag[17:23],16)
assert len(bin(R1)[2:])==17
assert len(bin(R2)[2:])==19
assert len(bin(R3)[2:])==21
R1_mask=0x10020
R2_mask=0x4100c
R3_mask=0x100002


for fi in range(1024):
    print fi
    tmp1mb=""
    for i in range(1024):
        tmp1kb=""
        for j in range(1024):
            tmp=0
            for k in range(8):
                (R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)
                tmp = (tmp << 1) ^ out
            tmp1kb+=chr(tmp)
        tmp1mb+=tmp1kb
    f = open("./output/" + str(fi), "ab")
    f.write(tmp1mb)
    f.close()
```


~~stream1,2,4做high之后：爆它！！！（超大声）~~

~~wait a minute ，二十多个十六进制爆不起爆不起~~

~~然后还是很咸鱼地用random爆了一场比赛，gg~~

作为一只小(da)萌(san)新(gou)，我首先~~用小本本~~把流程写了一遍

~~忽然发现我做过注释的代码不知道扔哪了，凉凉~~

首先，有一个len为24的flag它长这样：

`flag{balabalabala……}`

**下面我们把balabala……部分叫flag**

然后

```python
R1=int(flag[5:11],16)
R2=int(flag[11:17],16)
R3=int(flag[17:23],16）
```

这里我们就可以知道flag是十六进制的字符串了~~还爆条毛~~

然后flag长度为24-6=18，刚好分成R1,R2,R3三部分

又有
```python
assert len(bin(R1)[2:])==17
assert len(bin(R2)[2:])==19
assert len(bin(R3)[2:])==21
```

~~这个条件……当时我通过它找出上下限之后用来缩减了爆破范围~~

这里确定了R1，R3的二进制长度。

为什么特别地强调R1和R3？

因为这道题的突破点在——

我们先继续往下看

三个`range（1024）`和一个`range（8）`的循环里面，我们看看主要做了什么：
嗯，关键代码

`(R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)`

会出来个out，out和左移一位的tmp异或后会被转换成字符然后写入给出来的数据文件……

那么看来这个`out`就很重要了

再看看`single_round`做了什么

```python
def single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask):
    (R1_NEW,x1)=lfsr(R1,R1_mask)
    (R2_NEW,x2)=lfsr(R2,R2_mask)
    (R3_NEW,x3)=lfsr(R3,R3_mask)
    return (R1_NEW,R2_NEW,R3_NEW,(x1*x2)^((x2^1)*x3))
```
   
很好，在每一轮中,把R1R2R3和它们的mask输入，然后三部分独立进入线性反馈移位寄存器得到四个值：
`(R1_NEW,R2_NEW,R3_NEW,(x1*x2)^((x2^1)*x3))`

其中`(x1*x2)^((x2^1)*x3)`赋值给了上面提到的`out`

这里借用[这位大佬](http://blog.leanote.com/post/xp0intjnu@gmail.com/66c91498d13b)说的point：

当一串密钥流是通过多个lfsr独立生成后，再通过代数操作结合在一起时，就可以用**correlation attack**

我们再来看看具体是怎么攻击的

注意到输出来的第四个值：`(x1*x2)^((x2^1)*x3)`

这里是突破点，先写个真值表

x1 | x2 | x3 | out|
---- | ---|:--:|
    0    | 0  |  0|    0
    0  |  0  |  1 |   1
    0 |   1  |  0|    0
    0  |  1  |  1  |  0
    1   | 0  |  0  |  0
    1 |   0  |  1  |  1
    1  |  1 |   0  |  1
    1   | 1  |  1  |  1
   
 所以我们有，在所有可能性下：
```
P(x1 == out)  =  3/4
P(x2 == out)  =  1/2（和随机选择0或1一样）
P(x3 == out)  =  3/4
```
很明显我们就应该对x1和x3下手了

又因为x1和x2分别和R1、R2有关，所以我们可以先爆R1和R2








