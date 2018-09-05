---
layout: post
title: "Some small pieces of cryptography  "
date: 2018-09-3
excerpt: "非常分散，纯属瞎记"
tags: [Crypto]
feature: https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTr_u-n5r3O1MIxFBkyQObKHcXYQhDsnkiUZ29oOJxzhjI9Jm1m
comments: true
---

### Some small pieces of cryptography

~~今天没睡醒的时候被问要不要参加第四届全国密码技术竞赛，应了，所以刷了套那里的模拟题，算是复习了下密码学~~

链接：http://www.chinacodes.com.cn/exercises/gotoExercises.do

#### 0x01

有明文p为“Beijing 2008 Olympic Games”，密钥为（123）（56），密文为（）。

**A.i0mme2yaj0peBglGnOc i8is**
 B.i3mme2ya0peBglGnOc i8is
 C.i0nne2yaj0peBglGnOc i8is
 D.i3mme2ya0peBglGnOc i8iz

……这道题哇，太久不做古典密码都忘了，还以为是置换密码里面简单的分段->置换，结果是……比较像列置换这样子？
```
Beijin
g2008O
lympic
Games
```
然后按（123）（56）把每一列换位……

意思意思写一下吧

~~工资太低活得费力只有偶尔写几句智障代码才能勉强生存下去这样子~~

```python
>>> a = 'Beijing 2008 Olympic Games'.replace(' ','')+' '
>>> b = ''
>>> i = 0
>>> while i < len(a):
	b +=a[i+2]+a[i]+a[i+1]+a[i+3]+a[i+5]+a[i+4]
	b +='\n'
	i +=6
>>> print b
iBejni
0g20O8
mlypci
mGae s
>>> c = ''
>>> for i in range(6):
	c += b[i]+b[i+7]+b[i+14]+b[i+21]	
>>> print c
i0mmBglGe2yaj0penOc i8is
```

选A

一个看着挺全的CTF加解密归纳（主要是古典密码）：

https://hackfun.org/2017/02/22/CTF%E4%B8%AD%E9%82%A3%E4%BA%9B%E8%84%91%E6%B4%9E%E5%A4%A7%E5%BC%80%E7%9A%84%E7%BC%96%E7%A0%81%E5%92%8C%E5%8A%A0%E5%AF%86/


#### 0x02

5.下列密码体制可以抗量子攻击的是（ ）

 A.ECC
 B.RSA
 C.AES
 **D.NTRU**

介绍一下，NTRU是一个带有专利保护的开源公开密钥加密系统，使用基于格的加密算法来加密数据，与RSA加密算法和椭圆曲线加密算法不同，NTRU在基于量子计算机的攻击面前没有已知的弱点。

tql！

关于NTRU的一些详情可以看这里：

http://people.scs.carleton.ca/~maheshwa/courses/4109/Seminar11/NTRU_presentation.pdf

ctfwiki上也有提到：

https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/lattice/overview/

#### 0x03

被公钥加密后的对称密钥被称之为数字信封

详见：https://www.cnblogs.com/franson-2016/p/5520675.html

MI加密体制是一种构造多变量密码体制的方法。

最佳放射逼近分析方法是一种已知明文攻击的攻击方法。

在密码学中，雪崩效应（avalanche effect）指加密算法（尤其是块密码和加密散列函数）的一种理想属性。雪崩效应是指当输入发生最微小的改变（例如，反转一个二进制位）时，也会导致输出的不可区分性改变（输出中每个二进制位有50%的概率发生反转）。

盲签名(Blind Signature)除了满足一般的数字签名条件外，还必须满足下面的两条性质：

签名者对其所签署的消息是不可见的，即签名者不知道他所签署消息的具体内容。

签名消息不可追踪，即当签名消息被公布后，签名者无法知道这是他哪次的签署的。

参照：

https://blog.csdn.net/zhang_hui_cs/article/details/8728776


第一个被推广的背包公钥加密体制是Merkle-Hellman,在 1984年被攻破。

公开密钥加密最早由瑞夫·墨克（Ralph C. Merkle）在1974年提出，之后在1976年,惠特菲尔德·迪菲（Whitfield Diffie）与马丁·赫尔曼（Martin Hellman）两位学者 在《密码学的新方向》中提出。

希尔密码是由数学家Lester Hill于1929年提出来的。

Vigenere密码是由法国密码学家Blaise de Vigenere于1858年提出来的。


群签名方案是一种类似于数字签名的密码原语，其目的在于允许用户代表群签名消息，并在该群内保持匿名。   
只有群成员才能产生有效的群签名。其他任何人包括群管理员也不能伪造一个合法的签名。
给定一个群签名后，对除了唯一的群管理员以外的任何人来说，确定签名者的身份是不可行的，至少在计算上是困难的。 
群管理员在发生纠纷的情况下可以打开一个签名来确定出签名者的身份，而且任何人都不能阻止一个合法签名的打开。

详见：

https://blog.csdn.net/lovely_girl1126/article/details/79128788

RSA里p和q的选择：

https://wenku.baidu.com/view/6bcee345b307e87101f696ea.html

 A.p和q 要足够大的素数
 B.p 和 q 的差的绝对值要小
 C.p 和 q 要为强素数
 D.(p-1)和(q-1)的最大公因子要小

椭圆曲线计算：https://cdn.rawgit.com/andreacorbellini/ecc/920b29a/interactive/reals-add.html?px=-1&py=4&qx=1&qy=2


ZUC算法是中国自主设计的流密码算法，是中国第一个成为国际密码标准的密码算法，
以ZUC算法为核心算法的保密性和完整性算法在2011年年成为3GPP LTE标准。

SM2包含数字签名算法、密钥交换协议和公钥加密算法。

GM/T 0006《密码应用标识规范》定义的标识中，包括的数据编码格式：
无编码，DER编码，Base64编码，PEM编码，16进制数据的字符串，自定义编码格式预留。

中华人民共和国密码行业标准：
http://www.gmbz.org.cn/main/bzlb.html

绝密级事项三十年、机密级事项二十年、秘密级事项十年。

数字签名机制可以解决伪造、抵赖、冒充和篡改问题。 

从事电子认证服务的申请人应当服务许可的，应当持《电子认证服务许可证》到工商行政管理机关办理相关手续。

一切国家机关、武装力量、政党、社会团体、企事业单位和公民都有保守国家秘密的义务。

从事国家秘密载体制作、复制、维修、销毁，涉密信息系统集成，或者武器装备科研生产等涉及国家秘密业务的企业事业单位，应当经过保密审查，具体办法由国务院规定。

先写到这，下星期继续刷