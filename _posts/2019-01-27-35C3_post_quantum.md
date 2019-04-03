---
layout: post
title: "35C3 CTF post quantum "
date: 2019-01-07
excerpt: "……那就祝大家新年快乐吧"
tags: [Crypto,post-quantum,repetition code]
feature:  http://a4.att.hudong.com/25/12/20300543373089144254128899987_s.jpg
comments: true
---

# 35C3 post quantum

题目继续放最后

参考[majo的WP](https://sectt.github.io/writeups/35C3CTF/crypto_postquantum/README)

## 0x01 看个WP学到很多奇怪的新名词

#### TLDR 

short for "too long; didn't read"

太长不看

#### Post-quantum Cryptography

后量子密码

[能够抵抗量子计算机对现有密码算法攻击的]新一代密码算法。

#### Repetition code

以重複備份偵測錯誤、更正錯誤的代码

~~写到这才发现好像都学过~~

## 0x02 回顾题目

给了很多个明文和密文对，还有flag的密文

加密流程如下：

每次的明文都是两个字节，即16比特

↓

每个比特重复三次，记为C，其长度为48比特

``#add_encoding``

↓

随机生成一个48*48的只有0和1的矩阵，记为G

``columns = balabala``

↓

忘了说有一个key，长度是48比特

``keygen``

↓

矩阵G和秘钥key相乘

``y = matrix_vector_multiply(columns, self.key)``

↓

相乘的结果和明文y异或，此时的结果记为y，长度为48比特

``y ^= message``

↓

得到的y，每三个字符，随机选择其中的一个翻转

``add noise``

↓

得到密文

## 0x03 matrix_vector_multiply

这个乘法我开始有点懵，所以想仔细看看

代码如下：

```python
def matrix_vector_multiply(columns, vector):
    cols = len(columns)
    assert(cols == len(vector))
    rows = len(columns[0])
    result = BitVector(size=rows)
    for i, bit in zip(range(cols), vector):
        assert(len(columns[i]) == rows)
        if bit == 1:
            result = result ^ columns[i]
    return result
```
这里定义了一堆列``columns``和向量``vector``的乘法（。）

要求列数和向量长度一致

先让结果result是全零向量，48bit

然后遍历``columns``中的每个元素，如果其对应的``vector``中的比特是1，则与``result``异或

即如果``vector``中``[i,j,k……]``个为``1``，则所谓相乘结果就是``columns``中的``[i,j,k……]``个元素依次异或最后得到的是一个长度为48的比特向量

## 0x04 死亡原因 && 解决

没想到``add nosie``骚到可以用和一个48bit的e异或来表示……然后e可能的情况是``3**16``，可以爆破

所以题目可以简化为：

明文C
↓
密文``m = G*key^C^e``

所以有
``key = G的逆*(C^m^e)``

然后我们又知道flag的前四个字符是``35C3``

我们就能，爆e

## 0x05 e的爆破


~~递归写不出来………………~~

~~逆矩阵求不出来……………………………………………………~~

~~Rhy7hm复现这道题复现到自闭~~

所以……转换成……三进制……了……

写了两个进制转换函数……

```
#decimal base a to n base str
def turn(a,n):
    rs = ''
    i = a
    while i:
        rs = rs+str(i%n)
        i = i//n
    return rs[::-1]

#a:str,n base, to decimal base int
def rturn(a,n):
    rs = 0
    for i in range(len(a)):
        rs += int(a[i])*(n**(len(a)-i-1))
    return rs

```
看这非常敷衍的英文注释就知道我被这道题折腾得都坏掉了……

我之后的注释还用了拼音……

然后所谓爆破e……

就是……

```
for i in range(43046720):
    tr = BitVector(size=48)
    mask = turn(i,3).rjust(16,'0')
    tag = 0
    for j in mask:
        tr[tag + int(j)] ^= 1
        tag +=3    
    #tr is e
```




## 0x06 求逆矩阵

可以用sage求，但是sage和python结合暂时还没去搞……

可以用``np.linalg.inv(flag_00_G)``

这个方法正确率好像……有点低……？

因为求出来之后，把原来的G和这样求出来的逆矩阵相乘……行列式的值是``3.389530375974187e+26``

所以选择用的``.I``，但是要先类型转换成``Matrix類型``

求出来倒是好像很正确的样子了……但是……

……怎么感觉``matrix_vector_multiply``根本不是标准的矩阵相乘啊喂

……然后我发现……

**这个发现是错的**

if
``matrix_vector_multiply(G,key) = M``
thus
``key = matrix_vector_multiply(G的转置,M)``

想到大概是因为……感觉……key和一个全零的矩阵按这里的方法``multiply``……是key本身……然后在F2里……G和它的转置……矩阵乘法（异或）这样……是……全零……

……啊，搞错了

………………

要在F2里才行………………

忘……忘了F2是什么的可以看[维基](https://zh.wikipedia.org/wiki/%E6%9C%89%E9%99%90%E5%9F%9F)……

我搞到了F2里逆矩阵的求法…………

参考[Lainme's Blog](https://www.lainme.com/doku.php/topic/sage/chapter_02/section_08)……

就……如果懒得装sage的话……可以用[在线的](https://sagecell.sagemath.org/)……

```
M = MatrixSpace(GF(2),48,48)
A = M([0,1,1,……G矩阵的值……,1,0,0])
R = ~A
R.str()
```


……所以为什么那个看上不去不符合乘法规则的``matrix_vector_multiply``是……F2里面的……矩阵相乘？

举……个……例……子……

从``3*3``说起……

假如随机生成了三个向量……``0 1 1``、``0 1 0``和``1 0 0``

那么``columns``为

```http
0 0 1
1 1 0
1 0 0
```
注意column是……纵列……

这样的矩阵……

若key为
```
1
1
0
```

显然``matrix_vector_multiply(columns, key)``就是前两个向量异或……就……``0 1 1``^``0 1 0`` = ``0 0 1``……

如果是按矩阵乘法定义的话……

```http
0 0 1      1     0 + 0 + 0      0
1 1 0   *  1  =  1 + 1 + 0   =  0
1 0 0      0     1 + 0 + 0      1
```

至于为什么是对应的列依次异或呢……

因为依次异或就是依次相加呀……

0加任何数都不变所以就省了呀……所以为1的依次异或呀……

## 0x07 跑flag

然后我用python跑……

大概的代码是这样的……

嗯里面有很多错……很多很多………………

```
for i in range(43046720):
    tr = BitVector(size=48)
    mask = turn(i,3).rjust(16,'0')
    tag = 0
    for j in mask:
        tr[tag + int(j)] ^= 1
        tag +=3
    m = bytes('35','utf-8')
    #m = '\x51\x53'
    m = cipher_00.add_encoding(m)

    els = flag_00_y ^ m ^ tr
    guess_key = matrix_vector_multiply(flag_00_GG,els)
    cipher_01 = CodeBasedEncryptionScheme.new()
    cipher_01.key = guess_key
    tr_p = cipher_01.decrypt(flag_01)
    if tr_p == 'C3':
        with open('hhh','ab') as f:
            f.write(guess_key)
        print('find:',guess_key)
        fff = map(lambda x:'./data/flag_'+str(x).rjust(2,'0'),range(31))
        for i in fff:
            with open(i,'rb') as f:
                print(cipher_01.decrypt(f.read()))
    tag2 += 1
    if tag2%233 == 0:
        print('no:',tag2,r'/43046720',tr_p)

```

跑了好像一两个小时才跑到百分之一……

……算了一下跑完要51个小时，比比赛时间还多仨（。）

所以就跑去写C语言的版本了…………

那就……只写……爆破过程了……

数据都是python弄出来复制粘贴的……

复制粘贴代码如下………………

```
tr = ''
for i in flag_00_GG:
    tr = tr+str(i)

print(r','.join(tr))
```

我……到底……在写什么……

然后在C里

``int fla_00_GG[48][48] = {};``贴大括号里就好了…………………

……

写了个能爆出所有满足把前面俩密文解密``35C3``的keys……的C代码……

```
time ./c_pwn >keys

real	18m33.487s
user	9m1.902s
sys	0m0.326s

```

跑出来1107个key……问题不大……

再用python爆……

……没想到python慢到爆一千多个key都……要……超久………………

………………没爆出来


………………脚本我又改了……很多天……

发现两个问题…………

每次循环忘记重新初始化数组……

和…………

解密的时候忘记异或密文……


最后还是算是写出来了……………………

两个能在比赛时间（？）内做出来的脚本……

（好的我去死死

## 0x08 我写的exp……

```c
#C 脚本
#include <stdio.h>
#include <stdlib.h>

int matrix_vector_multiply(int columns[48][48],int vector[48],int rs[48]){
    int c;
  
    for(int i = 0;i<48;i++){
    if(vector[i] == 1){
        for (int j = 0;j<48;j++)
            rs[j] = rs[j]^columns[i][j];
    }//if
    }//for
    return rs;
}//m_v_m



int decode(int msg[48],int out[16]){
    for(int i = 0;i < 16;i++){
        if((msg[i*3] == msg[i*3+1]) || (msg[i*3] == msg[i*3+2]))
            out[i] = msg[i*3];
        else
            out[i] = msg[i*3 + 1];
        }//for
   
    return out;
    }

int main(){
    int flag_00_GG[48][48] = {1,1,1,1,0,1,0,1,0,1,1,1,0,1,0,1,1,1,0,0,1,0,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,0,0,0,0,1,1,0,1,0,0,0,1,1,0,0,1,1,0,0,1,0,0,0,0,0,1,1,0,1,0,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,0,1,1,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,0,0,0,1,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,1,0,1,1,0,1,1,0,0,0,0,1,1,1,1,0,1,0,0,0,0,0,0,1,1,0,1,0,1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,0,0,0,1,0,1,1,1,0,0,1,1,0,0,1,1,1,1,0,1,0,0,0,1,1,0,1,1,1,0,1,0,1,1,1,0,1,1,0,0,0,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,0,1,1,0,0,1,1,1,0,1,0,0,1,0,0,1,0,0,0,0,1,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,1,1,0,0,1,0,0,0,1,1,0,0,1,1,1,1,0,1,0,0,0,1,0,1,0,0,0,1,0,1,0,0,0,1,1,0,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,0,1,0,0,0,0,1,0,1,0,0,0,1,1,0,1,0,1,0,1,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,1,0,0,0,1,0,1,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,1,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,0,1,0,0,0,0,1,0,0,0,1,1,1,1,0,0,1,0,0,0,1,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,1,1,0,0,1,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,0,0,1,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,1,0,0,1,1,1,0,1,0,0,1,0,1,0,1,1,1,1,1,1,1,0,0,1,0,0,1,1,0,0,1,1,0,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,0,1,0,0,1,1,1,1,0,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,0,1,1,0,0,0,0,0,0,1,0,0,1,1,1,0,0,1,0,1,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,1,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,0,1,0,0,0,0,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,0,0,1,0,1,0,1,0,1,0,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1,1,0,1,0,0,1,1,1,1,0,0,1,0,0,0,0,0,0,1,0,0,1,1,1,0,1,1,0,1,1,0,1,0,0,1,1,0,1,0,1,1,1,0,0,0,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,1,1,0,0,0,1,1,0,0,0,1,1,0,1,0,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1,0,1,0,1,0,1,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,1,1,1,1,0,0,1,0,0,1,1,0,0,1,1,0,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,1,1,0,0,0,1,1,1,1,1,1,0,0,0,0,0,0,0,1,0,1,1,1,1,0,0,1,1,0,1,0,1,0,1,1,1,0,0,1,1,1,1,0,1,1,1,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,1,0,1,1,0,1,1,1,0,1,1,0,1,0,0,1,1,1,1,0,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,1,0,0,1,1,0,0,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,1,1,0,1,1,1,0,1,0,0,0,0,1,0,0,1,1,0,1,0,1,1,0,0,0,1,1,1,1,0,1,1,1,1,1,0,1,1,1,1,0,0,1,0,1,1,0,0,1,1,1,1,1,0,0,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1,1,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,1,0,0,0,1,1,1,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,0,0,1,0,0,0,0,1,1,0,0,0,0,1,0,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,0,1,0,1,0,1,1,1,0,0,1,0,0,1,1,1,0,0,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,1,1,0,1,0,0,1,1,0,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,1,0,0,1,1,1,0,1,1,0,1,1,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,1,1,0,1,1,0,0,0,0,1,1,1,0,1,1,0,1,1,0,0,1,0,1,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,0,0,1,0,0,0,0,0,0,1,1,1,1,1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,1,1,0,1,1,1,0,1,1,1,1,0,0,0,0,0,1,0,1,0,0,0,1,0,1,1,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,0,1,1,1,1,1,1,0,0,0,0,1,0,0,1,1,1,1,0,0,1,0,1,0,0,1,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,1,0,0,0,1,0,1,0,0,1,1,0,0,1,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,1,0,1,1,0,1,0,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,1,0,0,0,1,0,0,0,0,1,1,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,1,1,1,1,1,1,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,0,1,0,1,1,1,1,0,1,1,0,0,0,1,1,1,1,1,1,0,0,0,0,1,1,1,0,1,0,0,1,1,0,1,1,1,0,0,0,1,0,1,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,1,1,1,0,1,0,0,0,0,1,1,1,0,0,1,1,0,0,0,1,1,0,1,1,1,0,1,1,0,0,0,0,1,1,1,1,0,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,0,0,1,1,1,1,0,1,1,1,1,1,1,1,1,0,0,1,1,0,1,0,1,1,0,0,1,0,1,1,1,1,0,0,1,1,0,0,0,0,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,1,1,1,1,1,1,0,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,0,1,0,1,0,0,0,1,0,0,1,1,1,1,0,1,0,0,1,0,0,0,1,1,0,1,1,1,0,1,0,0,0,1,0,1,0,1,0,1,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,1,1,0,1,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,1,0,1,0,1,0,1,0,0,1,0,1,1,0,0,1,0,1,1,1,1,1,1,0,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,0,0,0,1,0,1,1,0,0,1,0,1,1,1,0,1,0,1,1,0,0,1,1,0,0,1,0,0,1,0,1,1,0,1,0,0,0,0,1,0,1,1,0,0,0,1,0,0,0,1,0,0,1,1,0,0,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1,1,0,1,1,1,1,1,0,1,1,0,0,0,0,0,1,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,1,0,0,1,1,1,0,0,1,0,0,0,0,0,0,1,1,1,1,0,1,1,0,1,0,0,0,0,0,1,0,0,1,1,1,0,0,0,0,1,1,0,1,0,0,1,1,0,1,1,0,1,1,1,0,1,1,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,1,0,1,1,1,1,1,0,1,1,1,0,1,1,1,0,0,0,1,0,0,1,0,0,0,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,0,0,1,1,1,0,0,0,0,1,1,0,1,0,0,0,1,0,0,0,1,0,0,1,0,1,0,1,0,0,0,0,1,0,1};

int m[48] = {0,0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,0,0,0,1,1,1,0,0,0,1,1,1};
//'35'
int flag_00_y[48] = {1,1,1,0,1,1,1,1,1,1,0,0,0,1,1,1,1,0,1,1,0,1,0,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,0,0,0,1,1,1,0,1,1};
//en('35')
int flag_01_y[48] = {1,0,1,0,0,0,0,1,0,0,1,1,1,0,0,0,1,1,0,0,0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,1,1,0,1,1,1,0,1};
//en('C3')
int flag_01_G[48][48] = {0,0,1,0,0,0,1,1,1,1,1,1,1,1,0,1,0,1,0,0,0,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,0,0,1,0,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,0,1,1,0,1,0,0,1,1,1,1,1,0,1,0,1,0,0,0,0,0,1,0,0,1,0,1,1,0,1,0,1,1,1,0,0,0,0,0,1,1,1,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1,1,0,0,0,1,1,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,0,0,1,1,0,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,1,1,1,0,1,1,0,0,1,1,0,1,1,0,0,0,1,0,1,0,1,0,1,1,1,0,0,0,0,1,0,0,0,0,1,0,1,1,0,1,1,1,0,0,1,0,1,0,1,1,0,0,1,0,0,1,0,0,0,1,1,1,1,0,0,1,1,0,0,0,0,1,1,1,1,1,1,0,1,1,0,1,0,0,1,1,0,0,0,0,1,1,1,0,1,0,1,1,0,0,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,0,1,0,0,0,0,1,0,0,0,0,1,1,1,1,1,0,1,1,1,0,0,0,1,0,1,1,0,0,0,0,0,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,0,1,0,1,0,1,0,0,1,1,0,1,0,0,0,0,1,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,0,1,0,1,0,1,0,1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,1,0,1,1,0,1,0,1,1,0,1,0,1,0,0,1,1,0,0,1,0,0,1,1,0,0,1,1,0,0,1,0,0,1,1,1,1,1,0,0,1,1,1,1,0,1,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,0,1,0,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,0,0,1,1,1,0,0,0,0,0,0,0,1,0,0,1,1,0,0,0,0,1,1,0,1,0,0,1,0,0,1,0,0,1,0,0,1,0,1,1,0,1,0,0,0,1,1,1,0,1,0,0,1,0,1,0,1,0,1,1,1,0,0,1,0,0,1,1,0,1,1,0,0,0,1,0,0,1,0,0,1,1,1,1,0,1,1,1,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,1,1,1,0,0,0,0,1,0,1,1,1,0,0,0,0,1,0,0,0,1,1,0,0,0,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,1,1,0,0,0,0,1,1,0,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,0,0,1,0,1,1,0,1,1,1,1,1,1,0,1,1,1,0,0,1,0,0,0,1,0,0,1,1,1,1,0,0,0,1,0,1,0,0,0,0,0,1,0,0,1,1,1,1,1,0,0,1,0,0,0,1,0,1,1,0,1,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,0,0,0,1,1,0,1,1,1,1,1,0,1,0,1,1,0,0,1,0,1,1,1,0,0,0,0,1,0,1,1,0,0,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,1,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,1,0,0,1,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,1,0,1,1,1,0,0,0,1,1,1,1,0,1,1,1,0,0,1,1,0,1,0,1,0,0,1,1,0,1,0,0,1,0,0,0,1,0,0,1,0,0,0,0,0,0,1,0,1,0,1,0,1,0,1,1,1,0,0,0,1,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,0,0,0,1,0,0,1,0,0,0,0,1,1,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,0,1,1,1,1,0,1,0,0,0,0,1,0,1,1,0,1,0,1,1,0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,1,1,1,0,1,1,0,1,1,0,0,0,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,0,0,1,1,0,1,1,1,0,0,1,1,0,1,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,0,1,0,0,1,1,0,0,1,0,1,0,0,0,1,0,1,0,0,0,0,0,1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,1,1,0,1,1,0,0,0,1,0,0,1,0,0,0,0,1,1,0,1,0,0,1,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,1,0,1,0,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1,1,0,1,1,0,1,0,1,0,1,0,0,0,0,0,1,0,0,0,1,1,1,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,0,1,0,1,0,1,1,0,1,1,0,1,0,0,0,0,0,1,1,0,0,0,1,0,0,1,0,1,0,0,1,0,0,0,0,1,0,0,1,0,1,1,1,0,1,0,0,0,0,0,1,0,0,1,1,0,0,1,1,1,0,1,0,0,0,1,0,1,1,1,1,1,1,1,0,1,1,1,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,1,1,0,1,0,1,1,0,0,1,0,0,1,0,1,0,0,1,0,0,0,1,0,0,1,1,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,0,0,0,1,0,0,0,1,1,1,0,1,1,0,0,1,0,0,1,1,0,0,0,1,0,0,1,0,0,1,1,0,1,0,0,1,0,1,0,1,0,1,0,0,1,1,1,1,1,1,0,0,1,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,1,0,0,0,1,1,0,0,0,1,1,1,1,0,0,1,1,1,1,0,1,1,0,0,1,1,1,1,0,0,1,1,0,0,0,1,0,0,1,1,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,1,0,1,1,1,0,0,1,0,1,0,0,0,0,0,1,0,0,1,1,1,1,1,0,1,1,0,1,1,0,0,0,1,0,1,1,1,1,0,0,1,0,0,0,1,1,1,0,0,0,1,0,0,0,1,0,1,1,0,1,0,0,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,1,1,1,1,0,0,0,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,1,0,1,1,1,1,0,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,0,0,0,0,0,1,0,0,0,0,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,1,0,1,1,1,1,0,0,0,0,0,0,1,0,1,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,1,1,1,1,1,0,0,1,0,0,1,0,1,0,1,1,1,0,0,0,0,1,1,0,1,0,0,1,1,1,0,1,0,0,0,0,0,1,1,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,1,0,0,1,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,1,0,1,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,0,1,0,0,0,1,1,1,0,1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,1,1,1,1,0,1,0,0,1,0,1,1,1,0,0,0,0,0,0,1,1,1,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,0,0,0,0,1,1,0,0,0,0,1,0,1,1,1,0,0,1,1,0,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,1,1,1,0,1,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,0,1,1,0,0,1,1,0,0,1,1,1,1,1,1,0,0,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,1,1,1,1,1,1,0,0,0,0,1,1,0,0,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,1,1,1,1,0,0,1,1,1,0,1,1,0,1,1,0,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,1,0,0,0,1,0,0,0,1,1,0,1,0,0,0,0,0,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,0,1,1,0,1,1,0,0,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,0,1,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,1,0,0,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,0};
int pt[16] = {0,1,0,0,0,0,1,1,0,0,1,1,0,0,1,1};
//'C3'

for(int ei = 0;ei<43046721;ei++){
    int eei = ei;
    int e[48] = {0};
    int ee[16] = {0};
    int tag= 0;
    while(eei){
        ee[tag++] = eei%3;
        eei/=3;
        }

    tag = 0;
    int tr = 0;
    for(int k=0;k<16;k++){
        tr = ee[k];
        e[3*k+tr] = 1;
        }

    int els[48] = {0};

    for(int j = 0;j<48;j++){
        els[j] = m[j]^e[j]^flag_00_y[j];
    }
    int guess_key[48] = {0};
    //这里一定要初始化为0
    int guess_pt[48] = {0};
    matrix_vector_multiply(flag_00_GG,els,&guess_key);

    int gs_pt[16];
    matrix_vector_multiply(flag_01_G,guess_key,&guess_pt);

    int real_guess_pt[48] = {0};
    

    for(int fuck=0;fuck<48;fuck++)
        real_guess_pt[fuck]= guess_pt[fuck] ^ flag_01_y[fuck];
       //记得还要和密文异或

    decode(real_guess_pt,&gs_pt);
    int flag = 0;
    for(int i = 0;i<16;i++){
        if(gs_pt[i] != pt[i]){
            flag = 1;
            break;
            }
        }//for ->guess pt = pt

    if(flag == 0){
        for(int i = 0;i<48;i++){
            printf("%d",guess_key[i]);
            }
        printf("\n");
        }//for ->print key
    }//burp e
        

    return 0;
}

```
耗时：
```
real	10m10.263s
user	9m49.728s
sys	0m0.545s

```
得到646个key


```python
#python 脚本
#!/usr/bin/python3

from BitVector import BitVector
from random import SystemRandom
from os import urandom
from numpy import *
import numpy as np
import itertools

inverse_error_probability = 3

def matrix_vector_multiply(columns, vector):
    cols = len(columns)
    assert(cols == len(vector))
    rows = len(columns[0])
    result = BitVector(size=rows)
    #print(result)
    for i, bit in zip(range(cols), vector):
        #print(i,bit)
        assert(len(columns[i]) == rows)
        if bit == 1:
            result = result ^ columns[i]
    return result



def bitvector_to_bytes(bitvector):
    return bitvector.int_val().to_bytes(len(bitvector) // 8, 'big')

def bitvector_from_bytes(bytes):
    return BitVector(size=len(bytes) * 8, intVal = int.from_bytes(bytes, 'big'))

class CodeBasedEncryptionScheme(object):

    @classmethod
    def new(cls, bitlength=48):
        key = cls.keygen(bitlength)
        return cls(key)

    def __init__(self, key):
        self.key = key
        self.key_length = len(self.key)
        self.random = SystemRandom()

    @classmethod
    def keygen(cls, bitlength):
        key = SystemRandom().getrandbits(bitlength)
        key = BitVector(size=bitlength, intVal = key)
        return key

    def add_encoding(self, message):

        message = int.from_bytes(message, 'big')
        message = BitVector(size=self.key_length // 3, intVal=message)
        out = BitVector(size=self.key_length)
        for i, b in enumerate(message):
            out[i*3 + 0] = b
            out[i*3 + 1] = b
            out[i*3 + 2] = b
        return out


    def decode(self, message):
        out = BitVector(size=self.key_length // 3)
        for i in range(self.key_length // 3):
            if message[i * 3] == message[i * 3 + 1]:
                decoded_bit = message[i * 3]
            elif message[i * 3] == message[i * 3 + 2]:
                decoded_bit = message[i * 3]
            elif message[i * 3 + 1] == message [i * 3 + 2]:
                decoded_bit = message[i * 3 + 1]
            else:
                assert(False)
            out[i] = decoded_bit
        return bitvector_to_bytes(out)

    def encrypt(self, message):

        message = self.add_encoding(message)

        columns = [
            BitVector(
                size=self.key_length,
                intVal=self.random.getrandbits(self.key_length)
            )
            for _ in range(self.key_length)
        ]

        y = matrix_vector_multiply(columns, self.key)
        y ^= message
        for i in range(self.key_length // 3):
            noise_index = self.random.randrange(inverse_error_probability)
            y[i * 3 + noise_index] ^= 1
        columns = [bitvector_to_bytes(c) for c in columns]
        columns = b"".join(columns)

        return columns + bitvector_to_bytes(y)

    def decrypt(self, ciphertext):
        y = ciphertext[-self.key_length // 8:]
        columns = ciphertext[:-self.key_length // 8]
        columns = [
            bitvector_from_bytes(columns[i:i+self.key_length // 8])
            for i in range(0, len(columns), self.key_length // 8)
        ]
        y = bitvector_from_bytes(y)
        y ^= matrix_vector_multiply(columns, self.key)
        result = self.decode(y)
        return result

cipher_01 = CodeBasedEncryptionScheme.new()
with open('keys','rb') as f:
    keys = f.read()
keys = keys.split()
tag = 0
real_flag = []
for i in keys:
    tg = 1
    rs = []
    i = list(map(lambda x:int(x)-48,i))
    i = BitVector(bitlist = i)
    cipher_01.key = i
    fff = map(lambda x:'./data/flag_'+str(x).rjust(2,'0'),range(31))
    for i in fff:
        with open(i,'rb') as f:
            ppt = f.read()
        ppt = cipher_01.decrypt(ppt)
        
        if max(ppt) < 127 and min(ppt) > 30:
            rs.append(ppt)
    #print('rs:',rs)

    rs = ''.join(list(map(lambda x:chr(x[0]) + chr(x[1]),rs)))
    #print('rs:',rs)

    if len(rs)>20:
        rs = list(map(str,rs))
        rs = ''.join(rs)
        print(tag,'/1127')
        print(rs)
        real_flag.append(rs)
    tag +=1

print(real_flag)
```
耗时：

```
real	1m11.280s
user	1m8.019s
sys	0m0.507s
```

得到：
```http
['35C3j-A,yt1KxF?u0.Jq8\\ni', '35C3K+EN\\_Du26ez"Xqb;6', '35C3*sWA8Su7f:W&mdkD\x1f.9i', '35C3vDb7X%N:SJmt5u@aDA', '35C3Hg*WAc3?jgO,z|A*&Qny', '35C3(r99 M<vk#Y-T#78;!bE', '35C3tgFD+ESmOA`js\\zfoq2DW.', "35C3_let's_hope_these_Q_computers_will_wait_until_we're_read", '35C3_y}p5aG${@ja~K<\\*f']
```


exp当然有很多很多很多可以改进的地方……但是……还有别的要做……就先跑路了……



## 0x09 关于唯一WP的正确使用姿势

~~所以9102年了，为什么还是只有一篇WP呢~~

WP就给出了一个[solve.c](https://sectt.github.io/writeups/35C3CTF/crypto_postquantum/solve.c)，C写的，没给出逆矩阵是怎么求出来的，用了15个for emmmm……

如果直接运行的话就会出来：

```
……

Oq�ˏu*5��N����)�J\�@��f��J��|�>K�����x�>@
35C3�=ɼT�L��^!���[E��ջ1���
                            KL���4�>�h�����pL K#nQ
��C��
35C3x.[��|�L;�ڒ
K26
   &�b4Q�\W�����Pn[�L�
�.u�@˲e�/
35C3e
      H�'�-B�5BH/�ks���CV(�F��3P|.Oz��6����P*`v���L#x
S�/g��C��#�E~����N}����>�;R-yW;������v#���=P�q�&f
35C3�\���*���F!�"ͷ�-��R
ξ��ky���cw��"M@���(�Wou�I

……
```

就很多个可能性……

所以正确的使用方式应该是……

```python
>>> with open('solve.txt','rn') as f:
...     tt = f.read()
... 
>>> tt = tt.split()
>>> len(tt)
1487
>>> rs = []
>>> #32,126
... 
>>> rs = []
>>> for i in tt:
...     if ord(max(i)) < 127 :
...             if ord(min(i)) > 30:
...                     rs.append(i)
... 
>>> rs
['35C3', '35C3', '35C3', 'u', 'T$', '35C3', '35C31x>', '35C3', '1', '(', '35C3mO', 'Z#', '35C3)', '35C3r{74uZ', '35C3/s', 'km', 'es', '@', '\\', '35C3#', '35C3', '1C', '{1N', 'W', '35C3', '35C3z', 'W', 'aQ', '35C3`P', 'K26', '35C3B', 'V-FB&5', '35C3', '35C3', '35C3+', 'j)', '{I', '35C3o', "35C3_let's_hope_these_Q_computers_will_wait_until_we're_ready", '35C3', '35C3{', '35C3', '35C3', "35C3iQ'k", 'A', '>', '35C3', '35C3-S', 'zN', 's', '35C3Bq-']
>>> 
```






## 题目

```python
#generate.py

from challenge import CodeBasedEncryptionScheme

from random import SystemRandom
from os import urandom



if __name__ == "__main__":
    cipher = CodeBasedEncryptionScheme.new()
    random = SystemRandom()
    for i in range(1024 + 512):
        pt = urandom(2)
        ct = cipher.encrypt(pt)
        with open("plaintext_{:03d}".format(i), "wb") as f:
            f.write(pt)
        with open("ciphertext_{:03d}".format(i), "wb") as f:
            f.write(ct)
        assert(pt == cipher.decrypt(ct))

    with open("flag.txt", "rb") as f:
       flag = f.read().strip()

    if len(flag) % 2 != 0:
        flag += b"\0"

    cts = list()
    for i in range(len(flag) // 2):
        cts.append(cipher.encrypt(flag[i*2:i*2 + 2]))

    for i, ct in enumerate(cts):
        with open("flag_{:02d}".format(i), "wb") as f:
            f.write(ct)
```

```python
#challenge.py
#!/usr/bin/python3

from BitVector import BitVector
from random import SystemRandom

inverse_error_probability = 3

def matrix_vector_multiply(columns, vector):
    cols = len(columns)
    assert(cols == len(vector))
    rows = len(columns[0])
    result = BitVector(size=rows)
    for i, bit in zip(range(cols), vector):
        assert(len(columns[i]) == rows)
        if bit == 1:
            result = result ^ columns[i]
    return result

def bitvector_to_bytes(bitvector):
    return bitvector.int_val().to_bytes(len(bitvector) // 8, 'big')

def bitvector_from_bytes(bytes):
    return BitVector(size=len(bytes) * 8, intVal = int.from_bytes(bytes, 'big'))

class CodeBasedEncryptionScheme(object):

    @classmethod
    def new(cls, bitlength=48):
        key = cls.keygen(bitlength)
        return cls(key)

    def __init__(self, key):
        self.key = key
        self.key_length = len(self.key)
        self.random = SystemRandom()

    @classmethod
    def keygen(cls, bitlength):
        key = SystemRandom().getrandbits(bitlength)
        key = BitVector(size=bitlength, intVal = key)
        return key

    def add_encoding(self, message):
        message = int.from_bytes(message, 'big')
        message = BitVector(size=self.key_length // 3, intVal=message)
        out = BitVector(size=self.key_length)
        for i, b in enumerate(message):
            out[i*3 + 0] = b
            out[i*3 + 1] = b
            out[i*3 + 2] = b
        return out


    def decode(self, message):
        out = BitVector(size=self.key_length // 3)
        for i in range(self.key_length // 3):
            if message[i * 3] == message[i * 3 + 1]:
                decoded_bit = message[i * 3]
            elif message[i * 3] == message[i * 3 + 2]:
                decoded_bit = message[i * 3]
            elif message[i * 3 + 1] == message [i * 3 + 2]:
                decoded_bit = message[i * 3 + 1]
            else:
                assert(False)
            out[i] = decoded_bit
        return bitvector_to_bytes(out)

    def encrypt(self, message):

        message = self.add_encoding(message)

        columns = [
            BitVector(
                size=self.key_length,
                intVal=self.random.getrandbits(self.key_length)
            )
            for _ in range(self.key_length)
        ]

        # compute the noiseless mask
        y = matrix_vector_multiply(columns, self.key)

        # mask the message
        y ^= message

        # add noise: make a third of all equations false
        for i in range(self.key_length // 3):
            noise_index = self.random.randrange(inverse_error_probability)
            y[i * 3 + noise_index] ^= 1

        columns = [bitvector_to_bytes(c) for c in columns]
        columns = b"".join(columns)

        return columns + bitvector_to_bytes(y)

    def decrypt(self, ciphertext):

        y = ciphertext[-self.key_length // 8:]
        columns = ciphertext[:-self.key_length // 8]
        columns = [
            bitvector_from_bytes(columns[i:i+self.key_length // 8])
            for i in range(0, len(columns), self.key_length // 8)
        ]
        y = bitvector_from_bytes(y)

        y ^= matrix_vector_multiply(columns, self.key)
        result = self.decode(y)
        return result
```

~~平均每次复现都要花个三四五六七八天，真的被虐到没脾气~~
