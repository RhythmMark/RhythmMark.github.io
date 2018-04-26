---
layout: post
title: "[复现]强网杯-StreamGame3-Writeup"
date: 2018-04-26
excerpt: "流密码的相关攻击了解一下."
tags: [StreamGame3,流密码, correlation attack,Crypto,CTF,Write up,强网杯]
feature: https://i2.wp.com/latesthackingnews.com/wp-content/uploads/2016/11/cryptography_word_cloud_l-800x445.png
comments: true
---
#[复现]强网杯-StreamGame3-Writeup

~~Rhythm终于肯填强网杯StreamGame3的坑了~~

~~找不到标题背景图，好难过~~

首先，这次复现感谢两位大佬的WP：

[Xp0int Team](http://blog.leanote.com/post/xp0intjnu@gmail.com/66c91498d13b)，[MF(admin)](http://wp.ilucky.xin/archives/173)

然后原题的加密数据文件在[这里](https://github.com/RhythmMark/RhythmMark.github.io)makings文件夹下有

----

0x01
----

这道题最重要是，R1R2R3分开爆QWQ
而且要找到x1、x3和out的相关QWQ

0x02
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

~~这个条件……当时我通过它找出上下限之后用来缩减了爆破范围，可惜我的爆破方向一开始就是错的，gg~~

这里确定了R1，R2和R3的二进制长度，也就是它们最大值最小值我们知道了

我们先继续往下看

三个`range（1024）`和一个`range（8）`的循环里面，我们看看主要做了什么：

嗯，关键代码

`(R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)`

这里会出来个out，out ~~和循环一次左移一位的tmp异或后会被转换成字符~~ 经过一丢丢变化写入给出来的数据文件

那么看来这个跟输出数据直接相关的`out`就很重要了

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
   
 所以我们有，在所有可能性下，概率——
```
P(x1 == out)  =  3/4
P(x2 == out)  =  1/2（和随机选择0或1一样）
P(x3 == out)  =  3/4
```
很明显我们就应该对x1和x3下手了

我们思路就有了：直接让out为x1，如果我们的R1（R1不用很麻烦就能转变成x1）蒙对了了的话，x1和out的重合率为75%，否则，**R1和out没有相关性**，就是0和1随机二选一，理论上重合率就是二分之一

**注意！！！三分之四是x1和out的重合率！！不是直接和密文的重合率！**


为了佐证这种猜想，我们可以先来意思意思爆破一下看看结果（具体怎么爆破下面讲）
![Alt text](http://chuantu.biz/t6/295/1524665011x-1404793328.png)
显然出来的重合率都是0.5左右


~~再来看看R1和x1的关系——因为在`single_round`中，~~
 ~~`(R1_NEW,x1)=lfsr(R1,R1_mask)`,所以**R1**对应`lfsr`的**R**，**x1**对应`lfsr`的**lastbit**~~

 ~~我们慢慢分析一下`lfsr`里输入R和输出lastbit的关系……~~
 
**分条毛，直接用阿**

其实现在思路很清晰了，我们可以爆破R1，使R1加密成x1，然后直接将x1当成out，再输出密文C1，然后我们又有正确的密文C2

然后就到重头戏——密文和out的关系了

看看out到密文经历了什么

```python
for fi in range(1024):
    print fi
    #产生的数据要输出到的文件名，但其实我们只要使用一个文件的数据就足够了
    tmp1mb=""
    for i in range(1024):
    #一个文件1024个字符
        tmp1kb=""
        for j in range(1024):
            tmp=0
            for k in range(8):
            #这个循环里，每次产生一个加密字符，并最后会写入文件      
                (R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)
                tmp = (tmp << 1) ^ out
            tmp1kb+=chr(tmp)
        tmp1mb+=tmp1kb
    f = open("./output/" + str(fi), "ab")
    f.write(tmp1mb)
    f.close()
```

如果我们每次从数据文件中提取一个字符c

对每个字符的形成过程而言，我们只要看下面这个就好了：

```python
tmp1kb=""
tmp=0
for k in range(8):
#这个循环里，每次产生一个加密字符，并最后会写入文件      
    (R1,R2,R3,out)=single_round(R1,R1_mask,R2,R2_mask,R3,R3_mask)
    tmp = (tmp << 1) ^ out
tmp1kb+=chr(tmp)

```
然后tmp我们是可以由加密数据文件中get到的，就是其中的每一个字符，重点是怎么从tmp逆出out

我们形象点看看其实它干了啥

我写了这个:

```python
# -*- coding: utf-8 -*-
import random
outt=''
#用来存放我随机产生的out们
tmp=0
for k in range(8):
    out = random.choice(['0','1'])
    outt += out
    out = int(out)
    print 'out',out
    tmp = (tmp << 1) ^ out
    print 'bint',bin(tmp)

print 'tmpd的二进制表示为：'.decode('UTF-8') ,str(bin(tmp)[2::]).rjust(8,'0')
#decode那里应该可以不用，就是我这里的编码环境比较尴尬
print '我随机生成的out为： '.decode('UTF-8') ,outt
```
它输出来这个：

```
out 0
bint 0b0
out 0
bint 0b0
out 1
bint 0b1
out 1
bint 0b11
out 0
bint 0b110
out 1
bint 0b1101
out 1
bint 0b11011
out 0
bint 0b110110
tmpd的二进制表示为： 00110110
我随机生成的out为：  00110110
```

emmmmm那就很一目了然喇，就是每一个密文字符的二进制，从左到右的0\1依次就是我们的out

所以我们可以用这样的姿势：

```python
def correlation(A, B):
    assert len(A) == len(B)
    N = intercept * 8
    d = 0
    for a, b in zip(A, B):
        for i in range(8):
            mask = 1 << i
            if ord(a)&mask == b&mask:
                d += 1
    return d / N
```

通过和mask & 的方法，来提取每次出来的out √

其中A和B就是我上面提到的C1和C2

然后作为不用python2和random库会很不开心的……魔改了一下大佬们WP里的代码：

大佬们的脚本是找出重合率的最大值，我直接random出重合率>0.66的就当是了，毕竟由最开始的截图得知……错误的R1得到的重合率好像都没超过0.6

 ~~其实本来还想用0.7的，其实可能应该在爆R2的时候加个次数限制超过就全部重新random？~~

这是解题脚本：

```python
# -*- coding: utf-8 -*-
import random
import time
start = time.clock()
def lfsr(R, mask):
#与题目一致
    output = (R << 1) & 0xffffff
    i = R & mask & 0xffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)
def single_round(R1, R1_mask, R2, R2_mask, R3, R3_mask):
#与题目一致
    (R1_NEW, x1) = lfsr(R1, R1_mask)
    (R2_NEW, x2) = lfsr(R2, R2_mask)
    (R3_NEW, x3) = lfsr(R3, R3_mask)
    return R1_NEW, R2_NEW, R3_NEW, (x1*x2)^((x2^1)*x3)

R1_mask = 0x10020 
R2_mask = 0x4100c
R3_mask = 0x100002
intercept = 64

def encrypt(R1, R2, R3):
    ret = ''
    for i in range(intercept):
        tmp = 0
        for k in range(8):
            (R1, R2, R3, out) = single_round(R1, R1_mask, R2, R2_mask, R3, R3_mask)
            tmp = (tmp << 1) ^ out
        ret += chr(tmp)
    return ret
	
with open('0', 'rb') as r:
    #读加密数据中的64个字节
    cipher = r.read(intercept)

	
def single_lfsr(R, mask):
    ret = ''
    for i in range(intercept):
	#一个文件有1024个字符我们只用64个
        tmp = 0
        for j in range(8):
		#模拟fin
            (R, out) = lfsr(R, mask)
	    #设x1 == out
            tmp = (tmp << 1) ^ out
	    #模拟成为真正密文前的最后一part加密
        ret += chr(tmp)
    return ret
#ret长度为64
	
def correlation(A, B):
#A是out，B是cipher，即tmp
    assert len(A) == len(B)
    #都是64 
    N = intercept * 8
	#一共这么多bit
    d = 0
    for a, b in zip(A, B):
	#遍历[猜测密文]和[真密文]
        for i in range(8):
            mask = 1 << i		
            if ord(a)&mask == ord(b)&mask:
                d += 1
    return float(d) / N
	
def guess1():
#爆破R1
    possible = 0
    while 1:
        r1 = random.randint(2**16, 2**17)
        #len(bin(R1)[2:])==17
        tr = single_lfsr(r1, R1_mask)
        #模拟用当前选择的R1出来的密文
        p = correlation(tr, cipher)
        #对比猜测密文和真密文中x1和out的重合率
        if p > 0.66:
            possible = r1
            break
    print 'r1, p:',r1, p
    print 'hex(possible):',hex(possible)
    # 0x1b9cb 0.7529296875 128bytes
    return hex(possible)
 
	
def guess3():
    possible = 0
    while 1:
        r3 = random.randint(2**20, 2**21)
        #len(bin(R3)[2:])==21
        tr = single_lfsr(r3, R3_mask)
        #模拟用当前选择的R3出来的密文
        p = correlation(tr, cipher)
        #对比猜测密文和真密文中x1和out的重合率
        if p > 0.66:
            possible = r3
            break
    print 'r3, p:',r3, p
    print 'hex(possible):',hex(possible)
    return hex(possible)


def brute_r2(a,b):
    while 1:
        r2 = random.randint(2**18, 2**19)
        g = encrypt(a, r2, b)
        if g == cipher:
            print 'r2:',hex(r2)
            # 0x5979c
            print 'flag{'+hex(a)[2::].rjust(6,'0')+hex(r2)[2::].rjust(6,'0')+hex(b)[2::].rjust(6,'0')+'}'
            break

r1 = guess1()
r3 = guess3()
brute_r2(int(r1,16),int(r3,16))
elapsed = (time.clock() - start)
print "Time used:",elapsed

```

结果：
![](http://chuantu.biz/t6/296/1524705397x-1566661211.png)

人品不太好花了半小时……


因为用的是random所以跑的时间就很考验人品阿……

~~欢迎在评论区说下跑了多久刺激下我~~






----
一些无关紧要的东西——

~~不想说开始居然卡了下在`float(d) / N`在python2里面是0~~

~~mark一下，在python3中，‘/’变成了精确除法，原来的改用‘//’表示。~~

---

最后，欢迎交流:D












