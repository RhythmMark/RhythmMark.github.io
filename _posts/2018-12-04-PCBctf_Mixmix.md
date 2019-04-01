---
layout: post
title: "鹏城杯 Mixmix+Quotes"
date: 2018-12-04
excerpt: "以此纪念还是运气型选手Rhy7hm的第一个非常水的二血"
tags: [Crypto,random.getrandbits,RSA-Partial-key exposure Attack,Feistel]
feature: http://www.51pptmoban.com/d/file/2017/04/22/17b3559220f03fb0c009f0c21944dd7c.jpg
comments: true
---


# 鹏城杯


## 鹏程杯Mixmix

题目放最后了

## 题目翻译：

用rsa加密flag->rsa中d的一半低位被对称加密->根据模数n、rsa密文c、随机生成秘钥前的624个状态和一半的私钥d求flag

### 详细一点的题目翻译：

```
#flag=open("flag","rb").read()
从文件flag里把flag拿出来->

#pad(m)
在flag追加随机字符成为flag1，使flag1的长度是32的倍数->

#cipher1(m)
对flag1进行rsa加密，返回long_to_bytes(d)[-len(long_to_bytes(d))/2-1:]，也就是私钥d的后半截pd，并把n和c写入文件fout->

#generateBOX()
使用random.getrandbits生成32个1024bit大小的秘钥，将之前的624个random.getrandbits生成的数据写入文件fout->

#pad2(m)
将pd在前面追加随机字符，使pd填充为长度为256Bytes的p_pd

#cipher2(m)
将p_pd进行对称加密，该加密算法结构为feistel，密文为en_pd，将en_pd写入文件fout

```

## 破绽：

1.``Predict MT19937 PRNG``

python中``random.getrandbits``在知道了624个状态之后的预测

2.RSA的``Partial-key exposure Attack``

d的一半泄露，套路太明显了……

---

## 死亡原因和过程：

### 0x01

预测random用了

https://github.com/tna0y/Python-random-module-cracker/blob/master/randcrack.py

这个轮子，正确率没到100%

而WP中使用的

https://github.com/kmyk/mersenne-twister-predictor

会更为精确

```python
with open ('r_st','rb') as f:
    status = f.read()

status = status.split()

#pip install mersenne-twister-predictor
from mt19937predictor import MT19937Predictor
predictor = MT19937Predictor()

#将题目所给的前624个在随机生成秘钥前随机生成的数据喂进去
map(lambda x:predictor.setrandbits(int(x,16), 32),status)

#预测出接下来生成的32个秘钥
BOX = map(lambda x:predictor.getrandbits(1024),range(32))

```

---
*关于导入status，我做题的时候死活split不了，就是无论怎么split还是完整的一个字符串……然后复现的时候这个问题不存在了？这就是传说中``Rhy7hm睡一觉才能解决``的问题吗*

---

### 0x02-对称加密

加密函数是这样的：

```
def singleround(m):
    L=bytes_to_long(m[0:128])
	
    R=bytes_to_long(m[128:256])
	
    nL=R
	
    nR=L^BOX[R%32]
	
    return pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR))
	

def cipher2(m):
    tmp=m
    for i in range(32):
        tmp=singleround(tmp)
    return tmp
```

~~长得跟DES有点像，~~很明显的~~Festal~~[Feistel](https://en.wikipedia.org/wiki/Feistel_cipher)结构

然后比赛的时候我写了这么一个解密：

```python
def re_singleround(m):
    L=bytes_to_long(m[0:128])
    R=bytes_to_long(m[128:256])
    nL=R
    
    for i in range(len(BOX)):
        nR = L^BOX[i]
        if nR ==  singleround(pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR)))[128:256]:
            break
    #print i
    return pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR))


def d_cipher2(m):
    #tmp=m[128:256] + m[0:128]
    tmp = m
    for i in range(32):
        tmp=re_singleround(tmp)
    return tmp
```

并写了这么一个测试来验证我写的解密是对的

```python
cc=cipher2(t).encode("hex")
de_cc=d_cipher2(cc.decode('hex')).encode('hex')

print 'de_cc:',de_cc

print 'cc:',cc

print de_cc == cc
```

我来翻译一下，写作``de_cc == cc``，读作``解密后的明文 等于 加密后的密文 ``

非常棒

我继续来回忆一下我是怎么想的

……我不想回忆了，Feistel都没记清

先复习一下[Feistel](https://zh.wikipedia.org/wiki/%E8%B4%B9%E6%96%AF%E5%A6%A5%E5%AF%86%E7%A0%81)

``加密``：

每轮将明文块拆分为两个等长的块L和R

![](https://wikimedia.org/api/rest_v1/media/math/render/svg/2834b974d6c8ccd6e54021b6b76d275b84920e87)
![](https://wikimedia.org/api/rest_v1/media/math/render/svg/28a52f6c266a67d155ae5ad05e99411db475609a)

则密文为![](https://wikimedia.org/api/rest_v1/media/math/render/svg/771c81f45399c6f498d55a4c5cf9d6cc7d20e6c9)

以我的理解就是一直交换，左边那块直接换成右边，右边那块进行异或操作之后再换到左边，最后一轮再交换一次。

``解密``的时候算法完全一样只要秘钥的使用顺序相反即可。

所以解密的重点是秘钥顺序要相反嘛

就好像N1CTF的[N1ES](https://ctf-wiki.github.io/ctf-wiki/crypto/blockcipher/des/#2018-n1ctf-n1es)一样

然后秘钥不是从1到32我就蒙了~~感觉超越了我智商的上限~~

``BOX[R%32]``，选取的秘钥和R的值有关，我要怎么取反呢

所以我忘了Feistel网络有个性质叫**轮函数F不必可逆**

所以，在

```python
def singleround(m):
    L=bytes_to_long(m[0:128])

    R=bytes_to_long(m[128:256])

    nL=R

    nR=L^BOX[R%32]

    return pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR))
```

中，``BOX[R%32]`` 就相当于``F(R,K)``，其中32应该就是Key。

解密函数直接复制粘贴加密函数就行了，不过题目中和标准Feistel有点不同的是它没了最后一步的交换（其实更科学一点说应该是最后一步在每一轮的变换中少了一步交换？不过我个人理解成在所有轮变换结束之后再多一次左右交换会更好理解）

所以其实解密函数应该这么写：

```
def f_singleround(m):
    L=bytes_to_long(m[0:128])
    R=bytes_to_long(m[128:256])
    nL=R
    nR=L^BOX[R%32]
    return pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR))

def f_cipher2(m):
    tmp=m[128:256] + m[0:128]
    #tmp = m
    for i in range(32):
        tmp=f_singleround(tmp)
    rs = tmp[128:256]+tmp[0:128]
    return rs

```

测试应该这么写：

```
cc=cipher2(t).encode("hex")

f_cc=f_cipher2(cc.decode('hex')).encode('hex')

print f_cc == t.encode('hex')
```

结果是能打印出true的

不过~~身为一个勇士~~勇于面对自己的愚蠢是Rhy7hm的自我修养

比赛的时候由于想找到解密时的秘钥顺序，由于秘钥都有了只是顺序不知道而已，所以就打算使用一个验证方式来每轮穷搜当时的秘钥……

具体方法如下：

观察最后一轮，若其输入是 L0 :: R0，那么输出的nL和nR即为：

nL = R0，nR = L0^BOX[R%32]

然后nL :: nR就是我最后拿到的密文。

所以如果正确的秘钥为K0，当我遍历到K0时，因为nR = L0^BOX[R%32]，所以L0 = nR ^BOX[R%32]，而我们又有加密函数，所以可以把解出来的L0::R0 灌入加密函数，看加密结果是不是和……

所以

……

总之我就写出了``nR ==  singleround(pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR)))[128:256]``这样的代码，好像是nR == R0：w的意思

而且通过了``密文解密后的明文 等于 加密后的密文 ``的验证

（因为这样的话根本找不到满足要求的K0，我用的又是

```
...
    for i in range(len(BOX)):
        nR = L^BOX[i]
        if nR ==  singleround(pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR)))[128:256]:
            break
...
```
所以次次都用了BOX[31]（其实当时print过出来的都是31也不知道我为什么会觉得它每次都用31可能是对的……），然后冥想可知用相同的key的话分Feistel出来的结果是跟原来的字符串一样的


~~一人血书跪求Rhy7hm滚出CTF圈系列~~

~~其实使用singleround的时候秘钥又变了~~

想说下这个函数

```
def pad_128(m):
    assert len(m)<=128
    if len(m)==127:
        return '\x00'+m
    if len(m)==128:
        return m
    assert False
```
其实不用太纠结，就是用来保证每一轮的block都是128bytes长的L和R组成而已……那个assert因为有上面的两个return，所以在正常情况下是不会执行的，嗯。


### 0x03-RSA Partial-key exposure Attack

其实这一步没死，因为在前面已经死透了……

当时做的时候拿着一个错误的pd（d的后半部分）尝试各种脚本……

就很凉

继续

先用刚写出来的解密函数把padding后的pd解一下

``dis = f_cipher2(m).encode('hex')``

此时得到的dis是

``os.urandom(256-len(pd))+long_to_bytes(d)[-len(long_to_bytes(d))/2-1:]``

其中pd为 ``long_to_bytes(d)[-len(long_to_bytes(d))/2-1:]``

以我的智商是要分析一下这个len是多长的……

~~经过多次的实践发现，~~字符串长度是偶数的时候就是后半段的d，奇数时就是后半段再往前加1个字符的d……

那么，我怎么确定，解出来的对称加密明文dis，哪些是os.urandom哪些是d呢？

我们已经有n和e，~~然后根据冥想可知d是不能小于n<e的（不然怎么mod n == 1）（是mod (p-1)*(q-1)谢谢）~~

就，


e*d = 1 + k*(p-1)*(q-1)

3*d < 1+k*n

k不能是0吧3*d为0还得了，所以k的最小值为1

3*d < 1+n

d < (1+n) / 3


所以d在这个题目中的最小值是


``7859664586550615387802462547856715214705008533865367860061387051013399146099427386291198965762490664033110100843126934840827269321608154329866339843534443572122169840646303292702817267391475884762089723971972964008709399525770254580941136363751062191885733622269529539894742065794911897599413340867221625233347185329306689714270287644491097623384411206161114558531584750319246366065610874307012818202280387764960025924486306415283008360383450629147216295004540939851306690680799699522631059356853055679369148868449324484912193678518791666073970282104875656159269565829495585199221920181478744201339626690460570845334``

其十六进制的长度是512，所以``len(long_to_bytes(d))``的最小值是512/2=256（两个字符表示一个十六进制，就是两个字符凑成一个十六进制来表示一个字符的ASCII……），``long_to_bytes(d)[-len(long_to_bytes(d))/2-1:]``在最短的情况下是``long_to_bytes(d)[-129:]``，也就是我们能保证至少``p_pd[-129:]``是``pd``

所以

```
dis = f_cipher2(m.decode('hex'))
dis = dis[-129:]
print len(dis)
pd = bytes_to_long(dis)
```
就能求出d的后半段pd：

``41553968686912790458952954242993376120770631907046753685913743296462656479519115622338767486057957865327928162894905159713476559759372878811027305942550917690129221521319505264770463830494835755547904306581759923536797408961014041078383923539917501415413031359824770485620647758572837271668506768858761339247563``

（这次的比赛好像没有防作弊什么的，所以每个人题目的pd应该都是一样的

---

现在我们有rsa中的n，e=3，明文c和一半的私钥pd了

然后可以直接谷歌找轮子

我找了三个

#### i

[SageMathを使ってCoppersmith's Attackをやってみる](http://inaz2.hatenablog.com/entry/2016/01/20/022936)里的``秘密鍵dの下位bitがわかっている場合``

~~这篇文章里提到了Coppersmith定理的n种使用方式，除了这道题之外的其他攻击类型还有sage的安装之类的在下一篇blog应该会提到~~

啊对了，虽然这里的n是以``long_to_bytes(n).encode("hex")``的形式给的，但其实``long_to_bytes``以我的理解就是``n.decode('hex')``，只是前者的操作对象是数字后者的操作对象是字符串，所以其实就是直接给了十六进制格式的n

```
# partial_d.sage

def partial_p(p0, kbits, n):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = n.nbits()

    f = 2^kbits*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-kbits), beta=0.3)  # find root < 2^(nbits//2-kbits) with factor >= n^0.3
    if roots:
        x0 = roots[0]
        p = gcd(2^kbits*x0 + p0, n)
        return ZZ(p)

def find_p(d0, kbits, e, n):
    X = var('X')

    for k in xrange(1, e+1):
        results = solve_mod([e*d0*X - k*X*(n-X+1) + k*n == X], 2^kbits)
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p


if __name__ == '__main__':
    n = 0xbac8178c6c942524e947f05b688d4f589b99428d4e932b6aa3cf9fc668436fe828271348451c43b52392dda7fca416d58ca39ddeafa012c4ca1b66b08c003296f1608e2e88184a23d400607be608fd2b75b3be14cedc678f27e1d5c601c4793ec599eff29e4ae568669fea83e917d584c6f45a99c81b50a235deb8094514b9dc6f8fc3746d2f9575b7d828c190f4eba1c719e13e9158c3874e19ad2aa886cbbe037a840ac277edc4ba4f9593331dd22575f13db757b5affc75325bec1310801712b3d6292700633dba4ccd1e3b842f749e29114de611204d40d4e032dd1d88e479c63a09ed6ec1c9fc68b757d84e6ddbeabce9f71a96cb0c5187875a527e81c3
    e = 3
    d = 41553968686912790458952954242993376120770631907046753685913743296462656479519115622338767486057957865327928162894905159713476559759372878811027305942550917690129221521319505264770463830494835755547904306581759923536797408961014041078383923539917501415413031359824770485620647758572837271668506768858761339247563

    beta = 0.5
    epsilon = beta^2/7

    nbits = n.nbits()
    kbits = floor(nbits*(beta^2+epsilon))
    d0 = d 
    print "lower %d bits (of %d bits) is given" % (kbits, nbits)

    p = find_p(d0, kbits, e, n)
    print "found p: %d" % p
    q = n//p
    print inverse_mod(e, (p-1)*(q-1))
```

跑出来d为

``15719329173101230775604925095713430429410017067730735720122774102026798292198854772582397931524981328066220201686253869681654538643216308659732679687068887144244339681292606585405634534782951769524179447943945928017418799051540509161882272727502124383771467244539059079789484131589823795198826681734443250466489631148083608378602690249331340288477433925901930416883386560607894108133072240151451713294504041574171909966081139950332854672625859935972900507941581759565393537375540648238054700355023950471918032942297781254286296194965889493933080236396888544403928268329653036490837233832639787140301937122334872345547``

得到flag：
```
>>> hex(pow(c,d,n))[2:-1].decode('hex')
',\x9d\x10$\x8ft\x08\x9c\xc1?\x93B\xc5W\xb8\xab6\x8f\xe4)\x11\x1fM\x99\xb1\xfd\xdd\xd3D\t\xf4\x11\x7f\xaf%\x98\xfeN$\x06\xac\x1a\xfel\x12\xd6tr\xfcO\x96\x9d\xa7u\xa9w\x18\xb4\xde\x9cC+W\xc6\x87Jf&\xbd\xb6\xa7+\x0f\xf0\xe8\xd8\xd6\xc6\x87\x8f\x16\x19~\xe5c]\xfc\xb1)\x87\x81\xb3\x8d\xb6}H\x14\xbb\xec\x9d|k\x8eW\x89\xa6\xfb\xe1\x7f\xc6\x0fbg\x9bs\xc1ek\xd0\x87\x01\xe1\xbd#i\x17x~I\xf5\xc3\xf0\xbdD\xa8\x88Pn\x8a\xfdx\x07\xe9.\x1egW\x8d\x04\xafh)~\x8b\xcd\xe5\x05)R\xcf\xec*\x9f\xe3\r\x10c\xf62ygcflag{m1x_flag_for_alot_of_challenges_rsa_block_stream_ctf}\xf2x6\x01\x86o'
```
看日期，樱花妹（咦？）博客里的这个脚本应该是来源于[Lattice based attacks on RSA](https://github.com/mimoo/RSA-and-LLL-attacks)，里面对原理有详细的介绍，我有空再写写。


#### ii

https://github.com/ValarDragon/CTF-Crypto/blob/master/RSA/RSATool.py的def halfdPartialKeyRecoveryAttack

#### iii

https://github.com/grocid/CTF/tree/master/CSAW/2016

后两个都有点问题，应该是我不会用。

---
## 参考：

https://xz.aliyun.com/t/3487#toc-8

https://xz.aliyun.com/t/3486#toc-18

## 题目：

```python
import os
import primefac
import random
from Crypto.Util.number import getPrime,long_to_bytes,bytes_to_long
flag=open("flag","rb").read()
print "++good good study, day day up++"
fout=open("output","wb")

def pad(m):
    tmp=m+os.urandom(16-len(m) % 16)
    if (len(tmp)/16) % 2 !=0:
        tmp+=os.urandom(16)
    return tmp
	
m=pad(flag)

def cipher1(m):
    tmp= bytes_to_long(os.urandom(172)+m)
    e=3
    p=getPrime(1024)
    q=getPrime(1024)
    n=p*q
    c=pow(tmp,e,n)
    d=primefac.modinv(e,(p-1)*(q-1)) % ((p-1)*(q-1))
	
    if pow(c,d,n)!=tmp:
        return cipher1(m)
		
    else:
        fout.write(long_to_bytes(n).encode("hex") + "\n")
        fout.write(long_to_bytes(c).encode("hex") + "\n")
		
        return long_to_bytes(d)[-len(long_to_bytes(d))/2-1:]


t=cipher1(m)

def pad2(m):
    assert len(m)<256
    return os.urandom(256-len(m))+m
	
t=pad2(t)


def generateBOX():
    for i in range(624):
        tmp=random.getrandbits(32)
        fout.write(long_to_bytes(tmp).encode("hex")+"\n")
    BOX=[]
    for i in range(32):
        BOX.append(random.getrandbits(1024))
    return BOX
BOX=generateBOX()

def pad_128(m):
    assert len(m)<=128
    if len(m)==127:
        return '\x00'+m
    if len(m)==128:
        return m

def singleround(m):
    L=bytes_to_long(m[0:128])
	
    R=bytes_to_long(m[128:256])
	
    nL=R
	
    nR=L^BOX[R%32]
	
    return pad_128(long_to_bytes(nL))+pad_128(long_to_bytes(nR))
	

def cipher2(m):
    tmp=m
    for i in range(32):
        tmp=singleround(tmp)
    return tmp

cc=cipher2(t).encode("hex")
fout.write(cc+"\n")
```
---

最后，拿了个~~送分题的~~二血，记录一下

![](https://github.com/RhythmMark/hello-world/blob/master/pictures/22222222.jpg?raw=true)

---

对了这场比赛有一题MISC叫**Quotes**，题目如下：
```http
My+mission+in+life+is+not+mer ely+to+survive+but to+thrive+and+to+do+so+w ith+s  ome+pass i on+some+compass ion+so me+humor+and+some+style
```
我没解出来，后来看了答案，大概就是
```c
Mymissioninlifeisnotmer 
elytosurvivebut 
tothriveandtodosow 
iths 
 
omepass
i
onsomecompass
ionso 
mehumorandsomestyle
```
去掉加号之后根据空格来分开字符串，数每一行的字符个数，然后1是a，2是b这样
```
>>> a = 'My+mission+in+life+is+not+mer ely+to+survive+but to+thrive+and+to+do+so+w ith+s  ome+pass i on+some+compass ion+so me+humor+and+some+style'
>>> b = a.replace('+','').split(' ')
>>> c = map(lambda x:len(x),b)
>>> c
[23, 15, 18, 4, 0, 7, 1, 13, 5, 19]
>>> d = ''.join(map(lambda x:chr(ord('a')+x-1),c))
>>> d
'word`games'
```
word games中间好像是空格，你们开心就好

~~希望出题人对象天天这么和出题人讲话~~





