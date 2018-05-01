---
layout: post
title: "【红帽杯】rsa system writeup"
date: 2018-05-1
excerpt: "有生之年能写比赛WP系列"
tags: [RSA,Franklin-Reiter Related Message Attack, Crypto,CTF,红帽杯,redhat]
feature: http://www.ruanyifeng.com/blogimg/asset/201307/bg2013070301.png
comments: true
---


#红帽杯 rsa system writeup


*首先，这道题拿了四……四血（超小声），其中一个脚本跑了才五个小时跑出来，表示很期待其他能做得更快的WP QWQ，这里先分享一下我的做法*

主要思路：构造padding使两次`要进行rsa加密的明文`m1 和 m2 只有最后一个字符不同 ->通过nc交互得到c1 和 c2 ->使用RSA的`Franklin-Reiter Related Message Attack`  ~~->因为脚本跑出来的明文不知道为什么少了5个字符所以用已有的n,e,c1,m1爆破->~~通过rsa明文和pad()函数 get flag

0x01 About padding
---

拿到代码（代码扔最后了），粗略一看，嗯首先有个len为38的flag，另这个flag为`origin_flag`，然后然后flag通过pad（）函数，即`flag = pad(origin_flag)`，之后能让你选择：
1.unpad（flag） ->flag = unpad(flag)+ raw_input ，其中后者是我们输入的字符串，长度不能超过256-38=218

然后很简单就能验证`unpad(pad(flag)) == flag`

可以参考以下的代码：

```python
def pro():
    for i in range(23):
        flag = ''
        for _ in range(38):
            flag += random.choice(list(string.lowercase + string.uppercase + string.digits))
        assert(len(flag) == 38)
        print unpad(pad(flag)) == flag
```
然后出来一堆true，验证成功


所以我们直接选择1的话，`flag = unpad(flag)+ raw_input` 其实就是 `flag = origin_flag+ raw_input`

看到这里就想到了
——**Franklin-Reiter Related Message Attack** ！（超大声）
还有`b00t2root '18`这道题：
```

msg + "qwerty"    RSA encrypted with (n,e) ---->  c1
msg + "asdfgh"    RSA encrypted with (n,e) ---->  c2


n = 114725527397185618184017233206819193913174443780510744606142335459665478168081417742295326326458510125306461590118257162988125409459000413629137879229803717947627133370343339582895822944017711093729671794212087753322731071609302218014807365556283824229308384059742494244873283137838666434755861643308137132991

e = 12289

c1 = 87410813732157727701928184577314318681587457726095432638836338681211650253979034474596959990411435773763619929643745595561018045828590610328140736165000754846648327232298646701600080979346670157972588491030528441191645554122003288005262778737855011793921980764813901447954145380508985385929190951189001811183

c2 = 13405530225102142120310029551994876557837309021095393214835868463875586021351445304878372433515568058695315045246405214821866800311993984428311760617739453096525618753380012567374424357402936368910846206438489444245873338816383688500972351617863313954864557810634214028546221991063291427532826592675208605764

Find msg.
```

然后就在想是不是，通过和nc交互两次，分别发送'1'和'2'作为padding，就能直接用和上题一样的姿势解出来了？

然后冷静下来发现，它还要`flag = pad(flag)`，也就是cmd = 1之后返回的，`flag = pad(origin_flag + raw_input)`

我们看看pad()函数做什么

```python
fake_flag = 'flag{' + '@'*32 + '}'
assert(len(fake_flag) == 38)
rs = pad(fake_flag)
print 'len after pad():',len(rs)
print 'string after pad():',rs

hope_m1 = pad(fake_flag + '1')
print 'hope_m1:',hope_m1
```

结果：
```
len after pad(): 256
string after pad(): Ú@ÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚ@ÚÚÚÚ@ÚÚÚÚ@ÚÚÚÚÚ@ÚÚÚÚÚÚÚÚ}ÚÚÚÚÚÚÚ@ÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚ@ÚÚÚÚÚÚÚÚÚfÚÚÚ@ÚÚÚ@ÚÚÚ@ÚÚ@ÚÚÚ@aÚÚÚgl@ÚÚÚÚ@ÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚ@ÚÚÚÚÚÚÚÚ@ÚÚÚÚÚ@Ú@ÚÚÚÚÚÚ@Ú@Ú@ÚÚÚÚÚÚÚ@ÚÚÚÚÚÚÚÚ@ÚÚÚÚ@ÚÚÚ@@ÚÚÚÚÚÚÚÚÚ@ÚÚ@ÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚÚ@Ú{ÚÚÚÚÚÚÚ@ÚÚ@@Ú
hope_m1: Ù@ÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙ@ÙÙÙÙ@ÙÙÙÙ@ÙÙÙÙÙ@ÙÙÙÙÙÙÙÙ}ÙÙÙÙÙÙÙ@ÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙ@ÙÙÙÙÙÙÙÙÙfÙÙÙ@ÙÙÙ@ÙÙÙ@ÙÙ@ÙÙÙ@aÙÙÙgl@ÙÙÙÙ@ÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙ@ÙÙÙÙÙÙÙÙ@ÙÙÙÙÙ@Ù@ÙÙÙÙÙÙ@Ù@Ù@ÙÙÙÙÙÙÙ@ÙÙÙÙÙÙÙÙ@ÙÙÙÙ@ÙÙÙ@@ÙÙÙÙÙÙÙÙÙ@ÙÙ@ÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙÙ@Ù{ÙÙÙÙ1ÙÙ@ÙÙ@@Ù
```

加上源代码的阅读，我们可以很清楚地get到，pad函数会返回一个长度为256的字符串，且将我们的输入，固定地映射到一个其中固定的位置，其他地方则用`'\x00'`填充

然后根据`pad(hope_m1)`后的结果也能发现，如果想我一开始想的直接发个'1'，经过pad()之后，'1'并不会出现在最后的位置。

所以我们要做的，就是想办法产生两个，pad()之后只有最后一个字符不同的字符串，
即：
```htmlbars
find:str1,str2 
sit: pad(str1) = msg + '1' = m1
     pad(str2) = msg + '2' = m2
```

然后使用cmd == '2'进行rsa加密，即得到两组密文c1和c2，就能利用Franklin-Reiter Related Message Attack得到RSA明文`pad(origin_flag+ raw_input)`了

至于cmd == '2'为什么是rsa加密，这个试几次 mul(x, y, z)，发现它就是x**y%z就能知道了。

我们要找到str1,和str2，首先要知道，原字符串str的哪个位置的字符，会被pad()塞进输出m的最后一个位置。

因为懒得仔细看代码，我是通过以下方法找出来的，算是二分法吧

```python
def find_padding():
    table = string.digits + string.lowercase + string.uppercase
    inde = ''
    for i in table:
        inde += i*4
    inde += '#'*8
    assert len(inde) == 256
    padd = pad(inde)
    tag = padd[-1]
    inde = ''
    for i in table:
        if i == tag:
            inde += '&*()'
        else:
            inde += i*4
    padd = pad(inde)
    tag = padd[-1]
    fin = 0
    for i in inde:
        if i == tag:
            print fin
        else :
            fin += 1
```
结果：125

那么我们就可以使raw_input() =`'a'*87+'1'+'b'*130 `和 `'a'*87+'2'+'b'*130`
来达到我们上述的目的
   
可以用以下代码验证一下，其实'g'是origin_flag的代替
```python 
def proof_padding():
    str1 = 'g'*38+'a'*87+'1'+'b'*130
    str2 = 'g'*38+'a'*87+'2'+'b'*130
    assert str1[125] == '1' and str2[125] == '2'
    print 'm1:',pad(str1)
    print 'm2:',pad(str2)
    print 'pad(str1)[:-1] == pad(str2)[:-1]?',pad(str1)[:-1] == pad(str2)[:-1]
```
结果：

```html
m1: agabaabababbbbbbababbabbabaabbbbaababbgababgabbagabaabgbaabaabbgabbababgbbabaabbaaaabbbbagaabbbbbbbgbbbgbbagbbagbagbbaggbbbgggbaabgaaabbbbbbbbbabbagbbabbbabgabaabgagabbabagbgbgbaaabbagbbbbababgbbabgbabggaabbaaabbgbagababbbbbbbaababbbbbababagagbbababagaagg1
m2: agabaabababbbbbbababbabbabaabbbbaababbgababgabbagabaabgbaabaabbgabbababgbbabaabbaaaabbbbagaabbbbbbbgbbbgbbagbbagbagbbaggbbbgggbaabgaaabbbbbbbbbabbagbbabbbabgabaabgagabbabagbgbgbaaabbagbbbbababgbbabgbabggaabbaaabbgbagababbbbbbbaababbbbbababagagbbababagaagg2
pad(str1)[:-1] == pad(str2)[:-1]? True
```
发送这两个padding，得到密文：

```
c1 = 0x2e95061645dba045d7083137aba0d7248e1e1effa7ad255439d60fdabd7dafa277cccad377602d4633a59724a924eec2a9ddf70a5082ada19c1e0ab12d02cb1fd12bf0153816c606c530de8dfba10994354dec0f8dc4545ff014377ac9441fbc8fbc2a4ddc37f1250bb123e8756628bce218356ababba112402d3354ab7e9562c332aad99dad35c3013e372e5847521c64c0db7e6fb6e7978376b409effab4e2a1919acb9b6767146b6946e9ddea05623bddcdef0da95b1f58036bd01fb9aa439c4fb52647c4619b06fd330604b993705c680eaab44a3b1c9ad85d1c4a225cf8461d646633be77be26d61d55408076f2a7ab78f07fe575ccfc38b06ee1343c89

c2 = 0x4d050fa5936549d50987564780dcbf2ab67b7fa8591fb89938eb6ed1351e34f858bc109e208e749ff23b02c1863bb5ffe8132cae92c002fc24a448ccdb83b3f7c9244b5cffbc4ab241b2736d3862da76239ef6c72cb70aa623aa8641ab67f9db89a18d7f6be890bfbf351ddb17c5f6447bca5875d062335f5e939ce214863f9caccdcfc08acb3af46381ada4f10fed27290490afe6675905b6841f282a3a9491c084578a828254b73caaf74722e87617724f18bc00d403f6390e1a0137305c76aec1697cb5cb78a7be0fa07bc6122de699f26cb486a371d0d5f10f92aa869171033132568d601c207bb1da88150e7288e2d8e8d2b504f4d960b27e589db482be
```

0x02 About Attaction
---

参考[这里](http://yocchin.hatenablog.com/entry/2018/03/22/194000)RSA-2 (Crypto 200)的解题脚本，跑出`pad(origin_flag + our_padding)`

```python
# solve.sage
from hashlib import sha256

def related_message_attack(c1, c2, diff, e, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+diff)^e - c2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

n = 0xBACA954B2835186EEE1DAC2EF38D7E11582127FB9E6107CCAFE854AE311C07ACDE3AAC8F0226E1435D53F03DC9CE6701CF9407C77CA9EE8B5C0DEE300B11DD4D6DC33AC50CA9628A7FB3928943F90738BF6F5EC39F786D1E6AD565EB6E0F1F92ED3227658FDC7C3AE0D4017941E1D5B27DB0F12AE1B54664FD820736235DA626F0D6F97859E5969902088538CF70A0E8B833CE1896AE91FB62852422B8C29941903A6CF4A70DF2ACA1D5161E01CECFE3AD80041B2EE0ACEAA69C793D6DCCC408519A8C718148CF897ACB24FADD8485588B50F39BCC0BBF2BF7AD56A51CB3963F1EB83D2159E715C773A1CB5ACC05B95D2253EEFC3CCC1083A5EF279AF06BB92F

e = 0x10001

c1 = 0x2e95061645dba045d7083137aba0d7248e1e1effa7ad255439d60fdabd7dafa277cccad377602d4633a59724a924eec2a9ddf70a5082ada19c1e0ab12d02cb1fd12bf0153816c606c530de8dfba10994354dec0f8dc4545ff014377ac9441fbc8fbc2a4ddc37f1250bb123e8756628bce218356ababba112402d3354ab7e9562c332aad99dad35c3013e372e5847521c64c0db7e6fb6e7978376b409effab4e2a1919acb9b6767146b6946e9ddea05623bddcdef0da95b1f58036bd01fb9aa439c4fb52647c4619b06fd330604b993705c680eaab44a3b1c9ad85d1c4a225cf8461d646633be77be26d61d55408076f2a7ab78f07fe575ccfc38b06ee1343c89

c2 = 0x4d050fa5936549d50987564780dcbf2ab67b7fa8591fb89938eb6ed1351e34f858bc109e208e749ff23b02c1863bb5ffe8132cae92c002fc24a448ccdb83b3f7c9244b5cffbc4ab241b2736d3862da76239ef6c72cb70aa623aa8641ab67f9db89a18d7f6be890bfbf351ddb17c5f6447bca5875d062335f5e939ce214863f9caccdcfc08acb3af46381ada4f10fed27290490afe6675905b6841f282a3a9491c084578a828254b73caaf74722e87617724f18bc00d403f6390e1a0137305c76aec1697cb5cb78a7be0fa07bc6122de699f26cb486a371d0d5f10f92aa869171033132568d601c207bb1da88150e7288e2d8e8d2b504f4d960b27e589db482be

pad1 = int('1'.encode('hex'), 16)
pad2 = int('2'.encode('hex'), 16)
diff = pad1 - pad2
m = (related_message_attack(c2, c1, diff, e, n) - pad2) >> (8 * 6)
flag = ('%x' % m).decode('hex')
print flag

```
脚本~~跑了五个多小时~~跑出来结果出来少了六个字符
只得到
```
a0abaabababbbbbbababbabbabaabbbbaababb3ababeabba1abaabebaabaabb}abbababbbbabaabbaaaabbbba2aabbbbbbbfbbb7bba1bba1ba2bba1abbbgl1baab7aaabbbbbbbbbabba7bbabbbab0abaabca7abbaba5b4b2baaabba3bbbbababdbbab6bab88aabbaaabbeba2ababbbbbbbaababbbbbababa6a{bbababa
```

0x03 About 爆破
---


因为我们知道，m2为：
```python
#print pad('g'*38+'a'*87+'2'+'b'*130)
agabaabababbbbbbababbabbabaabbbbaababbgababgabbagabaabgbaabaabbgabbababgbbabaabbaaaabbbbagaabbbbbbbgbbbgbbagbbagbagbbaggbbbgggbaabgaaabbbbbbbbbabbagbbabbbabgabaabgagabbabagbgbgbaaabbagbbbbababgbbabgbabggaabbaaabbgbagababbbbbbbaababbbbbababagagbbababagaagg2
```

所以只要爆破未知的三个flag的字符就好了

爆破脚本如下：
```python
import random

n = 0xBACA954B2835186EEE1DAC2EF38D7E11582127FB9E6107CCAFE854AE311C07ACDE3AAC8F0226E1435D53F03DC9CE6701CF9407C77CA9EE8B5C0DEE300B11DD4D6DC33AC50CA9628A7FB3928943F90738BF6F5EC39F786D1E6AD565EB6E0F1F92ED3227658FDC7C3AE0D4017941E1D5B27DB0F12AE1B54664FD820736235DA626F0D6F97859E5969902088538CF70A0E8B833CE1896AE91FB62852422B8C29941903A6CF4A70DF2ACA1D5161E01CECFE3AD80041B2EE0ACEAA69C793D6DCCC408519A8C718148CF897ACB24FADD8485588B50F39BCC0BBF2BF7AD56A51CB3963F1EB83D2159E715C773A1CB5ACC05B95D2253EEFC3CCC1083A5EF279AF06BB92F
e = 0x10001

def str2int(s):
    return int(s.encode('hex'), 16)

def mul(x, y, z):
    ret = 1
    while y != 0:
        if y & 1 != 0:
            ret = (ret * x) % z
        x = (x * x) % z
        y >>= 1
    return ret

table = 'abcdefghijklmnopqrstuvwxyz1234567890'

m = 9722845213791901732663300449502267181519287029399227919991165723765212746919573285666123706836489224463721089840743139418697832506327042473468203155630177368780079344951519409709317265190931146262131299556890026074104589249053353729833333467468275090862094080257690358117609775763346012911315954917158917319845657783307036691887791890465688849712792541903499790258630788961884582627874317825101835791850155350051658314231079041683430047429653079073954080831411213924413680884483234556480657665875404481385046287017978656946642717920537789787335724804044343956311862558019667399242904217349436479126652550744856887998
while 1:
    mssg = 'a0abaabababbbbbbababbabbabaabbbbaababb3ababeabba1abaabebaabaabb}abbababbbbabaabbaaaabbbba2aabbbbbbbfbbb7bba1bba1ba2bba1abbbgl1baab7aaabbbbbbbbbabba7bbabbbab0abaabca7abbaba5b4b2baaabba3bbbbababdbbab6bab88aabbaaabbeba2ababbbbbbbaababbbbbababa6a{bbababa'
    mssg += random.choice(table)
    mssg +='aa'
    mssg += random.choice(table)
    mssg += random.choice(table)
    mssg +='2'
    assert len(mssg) == 256
    signature = mul(str2int(mssg), e, n)
    if signature == m:
        print mssg
        break
```

得到`pad(origin_flag + our_padding)`为：
```
a0abaabababbbbbbababbabbabaabbbbaababb3ababeabba1abaabebaabaabb}abbababbbbabaabbaaaabbbba2aabbbbbbbfbbb7bba1bba1ba2bba1abbbgl1baab7aaabbbbbbbbbabba7bbabbbab0abaabca7abbaba5b4b2baaabba3bbbbababdbbab6bab88aabbaaabbeba2ababbbbbbbaababbbbbababa6a{bbababaaaaf92
```

0x04 About 还原
---

然后用下面代码get flag
其中s是用
```
fakeflag = 'abcdefghijklmnopqrstuvwxyz1234567890[]'+'-'*87+'1'+'+'*130
```
pad之后得到的字符串

```python 
>>> s = '-j-+--+-+-++++++-+-++-++-+--++++--+-++0-+-+l-++-i-+--+[+--+--++]-++-+-+w++-+--++----++++-v--+++++++a+++k++-f++-g+-5++-pc+++dbt+--+r---+++++++++-++-9++-+++-+3-+--+1-4-++-+-o+y+2+---++-7++++-+-+6++-+h+-+sq--++---++z+-n-+-+++++++--+-+++++-+-+-x-e++-+-+-u--8m1'
>>> dist = {}
>>> for i in range(len(s)):
		if s[i] not in dist.keys():
			dist[s[i]] = i		
>>> he = []
>>> for i in 'abcdefghijklmnopqrstuvwxyz1234567890[]':
	he.append(dist[i])
	
>>> miwen = 'a0abaabababbbbbbababbabbabaabbbbaababb3ababeabba1abaabebaabaabb}abbababbbbabaabbaaaabbbba2aabbbbbbbfbbb7bba1bba1ba2bba1abbbgl1baab7aaabbbbbbbbbabba7bbabbbab0abaabca7abbaba5b4b2baaabba3bbbbababdbbab6bab88aabbaaabbeba2ababbbbbbbaababbbbbababa6a{bbababaaaaf92'
>>> rs = ''
>>> flag = ''
>>> for i in he:
	flag += miwen[i]
>>> flag
'flag{116107e92518781a2b64ec2072d3f73e}'
```
就能get flag了

最后附上原题代码：

```python
import signal

n = 0xBACA954B2835186EEE1DAC2EF38D7E11582127FB9E6107CCAFE854AE311C07ACDE3AAC8F0226E1435D53F03DC9CE6701CF9407C77CA9EE8B5C0DEE300B11DD4D6DC33AC50CA9628A7FB3928943F90738BF6F5EC39F786D1E6AD565EB6E0F1F92ED3227658FDC7C3AE0D4017941E1D5B27DB0F12AE1B54664FD820736235DA626F0D6F97859E5969902088538CF70A0E8B833CE1896AE91FB62852422B8C29941903A6CF4A70DF2ACA1D5161E01CECFE3AD80041B2EE0ACEAA69C793D6DCCC408519A8C718148CF897ACB24FADD8485588B50F39BCC0BBF2BF7AD56A51CB3963F1EB83D2159E715C773A1CB5ACC05B95D2253EEFC3CCC1083A5EF279AF06BB92F
e = 0x10001

def pad(s):
    s += (256 - len(s)) * chr(256 - len(s))
    ret = ['\x00' for _ in range(256)]
    for index, pos in enumerate(s_box):
        ret[pos] = s[index]
    return ''.join(ret)

def unpad(s):
    ret = ['\x00' for _ in range(256)]
    for index, pos in enumerate(invs_box):
        ret[pos] = s[index]
    return ''.join(ret[0:-ord(ret[-1])])

def str2int(s):
    return int(s.encode('hex'), 16)

s_box = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

invs_box = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

def mul(x, y, z):
    ret = 1
    while y != 0:
        if y & 1 != 0:
            ret = (ret * x) % z
        x = (x * x) % z
        y >>= 1
    return ret

def welcom():
    signal.alarm(5)
    print r"""
 ____  ____    _      ______   ______ _____ _____ __  __ 
|  _ \/ ___|  / \    / ___\ \ / / ___|_   _| ____|  \/  |
| |_) \___ \ / _ \   \___ \\ V /\___ \ | | |  _| | |\/| |
|  _ < ___) / ___ \   ___) || |  ___) || | | |___| |  | |
|_| \_\____/_/   \_\ |____/ |_| |____/ |_| |_____|_|  |_|
"""

def main():
    welcom()
    flag = open('./flag', 'r').read()
    flag_len = len(flag)
    assert(flag_len == 38)
    flag = pad(flag)
    while True:
        print '''
1. sign flag
2. get signed flag
Please give me your choice :'''
        cmd = raw_input()
        if cmd == '1':
            assert(len(flag) == 256)
            flag = unpad(flag)[:flag_len] + raw_input('Please sign your flag (0 - %d): ' % (256 - flag_len))
            assert(len(flag) <= 256)
            flag = pad(flag)
            print 'Success'

        elif cmd == '2':
            signature = mul(str2int(flag), e, n)
            print 'Your signed flag ciphertext is : 0x%x' % signature

        else:
            print 'Bye bye'
            exit(0)

if __name__ == '__main__':
    main()


```