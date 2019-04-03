---
layout: post
title: "hitcon2018-lost-key"
date: 2018-12-30
excerpt: "Which make me lose heart?"
tags: [Crypto,RSA Byte Oracle]
feature: https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTtw1pTrHm7OLtl5atLXLDHWS2DUGyCn_zowx71zxRyRtqJgBTR
comments: true
---


# Lost Key

## 0x01 前期准备

题目惯例放最后

加解密是``教科书式的RSA``，跟[lost-modulus](https://rhythmmark.github.io//Paillier/)有点像，但是这次只能交互150次，而n的大小是1024比特，所以不能通过同样的方法得到n

还是选A加密选B解密，但是解密的话只会输出明文的最后一个字符

在这个RSA里，n未知，e未知

先写一下准备工作：

复制题目，加上所需的库：

```python
from pwn import *
import gmpy2
from fractions import Fraction
```

连接服务器：
```python
context.log_level = 'debug'
io = remote("xxx.xxx.xxx",xxxx)
io.readline()
en_flag = io.readline()
en_flag = en_flag[:-1]
#get en_flag
```

加解密：
```python
def common(cm,s):
    io.sendlineafter('cmd:',cm)
    io.sendlineafter('input:',s)
    a =io.readline()
    return a.strip()

def enc(s):
    return common('A',s)

def dec(s):
    return common('B',s)
```


## 0x02 get n


还是顺着[P4的WP](https://github.com/p4-team/ctf/tree/master/2018-10-20-hitcon/crypto_rsa)来

先说一个小技巧：

如果我们知道e的话，

然后又有一个加密机，

那么我们可以发送2和3给加密机加密，

然后就会返回  ``2**e mod n``和  ``3**e mod n``，

然后我们求``gcd(2**e - (2**e mod n), 3**e - (3**e mod n))``，

这得到的将会是``gcd(k1*n,k2*n)``，

显然是一个较小的n的倍数。

虽然我们现在不知道e，但我们也能用类似的方法去得到n。我们让服务器加密``2``和``2**2 = 4``

我们将会得到：

``t1 = 2**e mod n``和``t2 = 2**(2e) mod n``

然后，我们计算 ``t1**2 - t2``

即``(2**e mod n)**2 - (2**(2e) mod n)``

因为``t1**2`` = ``(2**e mod n)**2`` = ``(2**e - k1n)**2`` = ``2**(2e) + n的一个倍数``

而 t2 即``2**(2e) + k2*n``

所以两式子相减得到的是一个n的倍数

类似的我们可以通过加密``3``和``3**2=9``得到另一个n的倍数，通过求这两者的最大公因子，我们就能像之前介绍的方法一样，获得n或者一个较小的n的倍数了 

---

复现的时候装了一下gmpy2，``sudo pip install gmpy2``，如果说缺少``mpir-h``的话要：

```
apt-get install libgmp-dev
apt-get install libmpfr-dev
apt-get install libmpc-dev
```
参考万能（×）的[stackoverflow](https://stackoverflow.com/questions/40075271/gmpy2-not-installing-mpir-h-not-found)

---

至于这个``较小的n的倍数``有多少，我手测了一下（得到这个数之后扔[factordb](http://factordb.com/)进行分解）发现多数直接是n，偶尔出现较小的因子也没超过10，我就除2到11以内的数字好了

```
for i in range(2,12):
    if guess_n % i == 0:
        guess_n = guess_n/i

n = guess_n
```

至此我们用了四次交互的机会，得到了n

## 0x03 get flag

为了能更好地理解这道题get flag部分的过程，先来复习一下``RSA parity oracle``，[ctfwiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_chosen_plain_cipher/#rsa-byte-oracle)上有介绍

……

我觉得ctfwiki写得真好，我这里就~~不多说了~~只大概说一下我的理解吧

首先吧，我们已经知道了n，然后我们可以通过下面这样的操作来通过逐渐缩小明文P的范围来得到P，我们这里的P就是flag

### i)

首先我们发送``(C*256)**e mod n``给服务器解密，

C是密文，后面那堆东西可以通过加密256来得到

```
C*256**e mod n 
= (flag*256)**e mod n
= flag**e mod n + 256**e mod n 
= En(flag)*En(256) 
```

然后服务器会返回：

``256*P mod n``，我们这里让它为T，注意我们只能得到T的最后一个字符，记为``T[-1]``。

让``T = 256*P mod n = 256*P - k1*n``两边同时 mod 256，

``T[-1] = 256*P - k1*n mod 256``，其中``0 <= 256*P - k1*n < 256``

所以就能轻易得出``(k1*n)/256 <= P < (n+k1*n)/256``这一不等式

然后这里的k1是确定的，因为不能存在第二个不同的k满足``T[-1] = 256*P - k1*n``

反证法如下：

if ``256*P - k1*n == 256*P - k2*n ``

=> ``k1*n == k2*n ``

=> ``k1 == k2 ``

~~笔者数院之耻，上述证明写得胆战心惊，如有错误欢迎提出，谢谢~~

那怎么得到这唯一的k呢？既然我们知道，``256*P - k1*n mod 256``=`` - k1*n mod 256``被其值``T[-1]``唯一确定，我们就能遍历所有的k1，显然可能的取值为0到255，来得出一个k和T[-1]的对应表

笔者用的代码如下：
``kmap = map((lambda x:(-1*x*n)%256 ),range(256))``

这样之后我们得到``T[-1]``后，就能通过``kmap.index(T[-1])``来得到此时的k值了

### ii)

下一步，我们会发送``(C*256*2)**e mod n``来给服务器解密，也就是第一步发送的内容乘上``256**e mod n``，得到``C*256*2 mod n``

同理，我们能得到

``(k2*n)/(256**2) <= P < (n+k2*n)/(256**2)``这样的表达式

这里的k2是

``T的最后两个字符 = 256*P - k2*n mod 256方``

但是我们这次是256的平方而不是256，不能简单地通过第一步的方式来获取k2了，怎么办呢？

问题不大，注意到，第一步我们得到了

``(k1*n)/256 <= P < (n+k1*n)/256``

这样的不等式，

即``(256*(k1*n))/256方 <= P < (256*(n+k1*n))/256方``

然后第一步和第二步的P的范围要有交集才行，毕竟flag是存在的……

然后我们又有，第一步得到的k1小于256，第二步得到的k2小于256的平方

我们不妨令``k2 = 256*x + y``

即第二步得到的式子为：

``(256*x*n+y*n)/(256**2) <= P < (n+256*x*n+y*n)/(256**2)``

显然x只能等于k1，而y和第一步中的k1一样，和此时的T[-1]唯一对应

所以``k2 = k1*256 + kmap.index(T[-1]) ``

### iii)

以此类推，在第三步的时候，我们能得到

``(k3*n)/(256**3) <= P < (n+k3*n)/(256**3)``

此时

``k3 = k1*256*256 + k2*256 + kmap.index(T[-1]) ``

那个T是每一步返回来的结果，不是一样的

然后慢慢逼近，我们就能得到P的值了

至于要进行到第几步才能得到flag，以笔者的数学素养是不知道的，所以笔者写了个这样的代码：

```
while (tag < 133):
    payload = payload * mul
    lb = int(dec(long_to_bytes(payload).encode('hex')),16)
    rsk = 256*rsk+kmap.index(lb)
    left = Fraction(rsk,(256**tag))
    right = Fraction((rsk+1),(256**tag))
    tag += 1
    print long_to_bytes(n*left)
```

然后笔者就看着print出来的内容从乱码到半个flag到整个flag就ctrl+c……

好吧其实笔者挣扎一下还是能解释的

因为n是个1024比特的数，然后``log(2**1024,256) = 128``

所以``256**128``就大于等于n了，此时

``(k*n)/(一个大于n的数) <= P < (n+k*n)/(一个大于n的数)``

即

``(k*n)/(一个大于n的数) <= P < (k*n)/(一个大于n的数)+n/(一个大于n的数)``

所以P的取值范围已经是个小数了，此时将极大值向下取整就可以了。


---

注意一下写脚本的时候有分数不要直接用除法，要用``Fraction``

然后n的话要最后再乘上，因为使用Fraction的话如果参数是mpz好像会有点麻烦。

---


## 0x04 exp如下

```
#!/usr/bin/env python
from Crypto.Util.number import *
from gmpy import *
import os,sys
from pwn import *
import gmpy2
from fractions import Fraction

def common(cm,s):
    io.sendlineafter('cmd:',cm)
    io.sendlineafter('input:',s)
    a =io.readline()
    return a.strip()

def enc(s):
    return common('A',s)

def dec(s):
    return common('B',s)

io = remote("pwn.sixstars.team",23507)
io.readline()
en_flag = io.readline()
en_flag = en_flag[:-1]
#get en_flag

two = int(enc('\x02'.encode('hex')),16)
four = int(enc('\x04'.encode('hex')),16)
three = int(enc('\x03'.encode('hex')),16)
nine = int(enc('\x09'.encode('hex')),16)
guess_n = gcd(two**2-four,three**2-nine)

for i in range(2,12):
    if guess_n % i == 0:
        guess_n = guess_n/i

n = guess_n
#get n

kmap = map((lambda x:(-1*x*n)%256 ),range(256))
mul = int(enc('\x01\x00'.encode('hex')),16)
#mul = 256**e mod n

flag = ''
rsk = 0
tag = 1
payload = int(en_flag,16)
while (tag < 129):
    payload = payload * mul
    lb = int(dec(long_to_bytes(payload).encode('hex')),16)
    print lb
    rsk = 256*rsk+kmap.index(lb)
    left = Fraction(rsk,(256**tag))
    right = Fraction((rsk+1),(256**tag))
    tag += 1
    print long_to_bytes(n*right)
```

也就五十多行，问题不大。

~~写了三天（×）~~




## 0x05 题目

```
#!/usr/bin/env python
from Crypto.Util.number import *
from gmpy import *
import os,sys

sys.stdin  = os.fdopen(sys.stdin.fileno(), 'r', 0)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

def genKey():
  p = getPrime(512)
  q = getPrime(512)
  n = p*q
  phi = (p-1)*(q-1)
  while True:
    e = getRandomInteger(40)
    if gcd(e,phi) == 1:
      d = int(invert(e,phi))
      return n,e,d

def calc(n,p,data):
  num = bytes_to_long(data)
  res = pow(num,p,n)
  return long_to_bytes(res).encode('hex')

def readFlag():
  flag = open('flag').read()
  assert len(flag) >= 50
  assert len(flag) <= 60
  prefix = os.urandom(68)
  return prefix+flag

if __name__ == '__main__':
  n,e,d = genKey()
  flag =  calc(n,e,readFlag())
  print 'Here is the flag!'
  print flag


  for i in xrange(150):
    msg = raw_input('cmd: ')
    if msg[0] == 'A':
      m = raw_input('input: ')
      try:
        m = m.decode('hex')
        print calc(n,e,m)

      except:
        print 'no'
        exit(0)


    elif msg[0] == 'B':
      m = raw_input('input: ')
      try:
        m = m.decode('hex')
        print calc(n,d,m)[-2:]
      except:
        print 'no'
        exit(0)


```

