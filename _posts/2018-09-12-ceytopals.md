---
layout: post
title: "ctfwiki_Crypto_overview之cryptopals"
date: 2018-09-12
excerpt: "做了前三题就跑路了（。）这篇文章由于过于菜也被屏蔽了……"
tags: [ctfwiki,Crypto,cryptopals]
feature: https://avatars3.githubusercontent.com/u/29177726?s=400&v=4
comments: true
---

---

我发现

https://cryptopals.com/

好好玩……

（虽然不太会玩

于是不务正业地秒了前三题

1.Convert hex to base64

```
from base64 import *
def hex2b64(s):
    return b64encode(s.decode('hex'))
```

2.Fixed XOR

```py
def xor(a,b):
    return ''.join(chr(ord(x)^ord(y)) for x,y in zip(a,b))
```

3.Single-byte XOR cipher

这题第一反应是写循环遍历所有可能性，print出结果都为可见字符的然后肉眼看……

```py
def single_byte_xor_loop(s):
    for i in range(0,256):
        rs = ''.join(chr(ord(x)^i) for x in s)
        if max(rs) <= '~' and min(rs) >=' ':
            print rs
```

结果：

```html
\pptvqx?R\8l?svtz?~?opjq{?py?}~|pq
Q}}y{|u2_Q5a2~{yw2s2b}g|v2}t2psq}|
Vzz~|{r5XV2f5y|~p5t5ez`{q5zs5wtvz{
Txx|~yp7ZT0d7{~|r7v7gxbys7xq7uvtxy
Kggcafo(EK/{(dacm(i(xg}fl(gn(jikgf
Jffb`gn)DJ.z)e`bl)h)yf|gm)fo)khjfg
Hdd`bel+FH,x+gb`n+j+{d~eo+dm+ijhde
Nbbfdcj-@N*~-adfh-l-}bxci-bk-olnbc
Maaeg`i.CM)}.bgek.o.~a{`j.ah.loma`
Cooking MC's like a pound of bacon
Bnnjhof!LB&r!mhjd!`!qntoe!ng!c`bno
Ammikle"OA%q"nkig"c"rmwlf"md"`caml
@llhjmd#N@$p#ojhf#b#slvmg#le#ab`lm
Gkkomjc$IG#w$hmoa$e$tkqj`$kb$fegkj
Fjjnlkb%HF"v%iln`%d%ujpka%jc%gdfjk
Eiimoha&KE!u&jomc&g&vishb&i`&dgeih
Dhhlni`'JD t'knlb'f'whric'ha'efdhi
```
显然明文为``Cooking MC's like a pound of bacon``

但是题目要求设置一个对明文的评分，这点让我有点脑壳疼

首先我的第一反应是，根据英文的字符频率，``e``是频率最大的，所以可以断定``密文字符串中出现频率最大的字符和e异或就是key``，但是一看明文e只出现了一次就……gg了

//啊这里主要是忽视了还用空格的存在……[维基百科](https://zh.wikipedia.org/wiki/%E5%AD%97%E6%AF%8D%E9%A2%91%E7%8E%87#cite_note-9)上毕竟还有一句``英语中空格出现的频率比使用最多的字母（e）还稍稍多点[9]（约为107%）``

如果是按照这个思路可以这么写：
```
def single_byte_xor_single_frenquency(s):
    t = s[0]
    for i in s:
        t = i if s.count(t) < s.count(i) else t
    key = ord(t)^ord(' ')
    return ''.join(chr(ord(x)^key) for x in s)
```

注：参数要先.decode('hex')
注2:使用三元运算符的时候别漏了else


当然正确答案不能这么简单的……正确答案它……是要评分的……


参考：

https://laconicwolf.com/2018/05/29/cryptopals-challenge-3-single-byte-xor-cipher-in-python/

↑这个在字母频率表里加了空格

↑评分方法是：
``sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])``

即遍历字符串，把``每个字符*该字符在英语中的频率``求和

---
彩蛋：

python3中，bytes.fromhex(hexstring)使一个十六进制格式的字符串转化为一个整数不可变序列

如：

```py
hexstring = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
>>> ciphertext = bytes.fromhex(hexstring)
>>> ciphertext
b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76'
>>> ciphertext[0]
27
>>> ciphertext[1]
55
>>> 0x1b
27
```

---
彩蛋：
按字典中的某个关键字排序：

``sorted(potential_messages, key=lambda x: x['score'])``

---

https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py


↑这篇用的评分方法是：

``math.sqrt(FREQUENCY_TABLE.get(char, 0) * y/total_characters) for char, y in c.items()``


彩蛋：计数统计
```
>> from collections import Counter
>>> a
{'b': 6}
>>> a = [111,2,333,111]
>>> Counter(a)
Counter({111: 2, 2: 1, 333: 1})
```



继续ctfwiki

基于秘钥的凯撒密码：

如 ``XMan 一期夏令营分享赛宫保鸡丁队 Crypto 100 ``

```
密文：s0a6u3u1s0bv1a
密钥：guangtou
偏移：6,20,0,13,6,19,14,20
明文：y0u6u3h1y0uj1u
```
---

Atbash Cipher

```
明文：A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
密文：Z Y X W V U T S R Q P O N M L K J I H G F E D C B A
```

solve:http://www.practicalcryptography.com/ciphers/classical-era/atbash-cipher/

---

仿射密码：

（完了我好像在回忆童年那样（不是

E(x) = a*x + b mod m，a和m互素
D(x) = a的逆元*(x-b) mod m

若知道两个明密文对即可利用两式相减解出a和b


彩蛋：``'%02x' % c``表示以十六进制形式输出02 表示不足两位，前面补0输出










