---
layout: post
title: "【一个Crypto手的自我修养】pwntools使用了解一下"
date: 2018-04-27
excerpt: "我只是想用来做密码题而已……pwn手？那是以后的事喇"
tags: [pwntools, python]
feature: https://warehouse-camo.cmh1.psfhosted.org/16d82a21c9635a10273ddd2595958d6c66216963/68747470733a2f2f6769746875622e636f6d2f47616c6c6f70736c65642f70776e746f6f6c732f626c6f622f737461626c652f646f63732f736f757263652f6c6f676f2e706e673f7261773d74727565
comments: true
---


#pwntools使用了解一下

偶尔密码题会给出个nc，不学点pwntools ~~当然zio、socket之类的也行，不过个人喜欢pwntools多一点~~  ~~pwntools虐我千百遍我待pwntools如初恋是这样的喇~~ 根本活不下去

~~还记得当年nextrsa解出来一关之后帮我写脚本的队友睡了自己写个sendline一写就错一写就错的惨痛回忆~~

使用教程的话网上已经很多了，这里主要记录一下自己学习过程中踩的一些坑？

因为懒得自己搞服务端 ~~其实就是我搞出来大概要一年~~ 所以借用了[DCTF-安全通信](http://ddctf.didichuxing.com/challenges#%E5%AE%89%E5%85%A8%E9%80%9A%E4%BF%A1)的端口

首先

`from pwn import *`

这个没什么好说的……

然后，我大概暂时只会用到这两个模块

**连接**
本地 ：sh = porcess("./level0")

远程：sh = remote("127.0.0.1",10001)

关闭连接：sh.close()  


**IO**

*发送*

sh.send(data)  发送数据

sh.sendline(data)  发送一行数据，相当于在数据后面加\n

---
*接收*

sh.recv(numb = 2048, timeout = dufault)  接受数据，numb指定接收的字节，timeout指定超时

sh.recvline(keepends=True)  接受一行数据，keepends为是否保留行尾的\n

sh.recvuntil("Hello,World\n",drop=fasle)  接受数据直到我们设置的标志出现

sh.recvall()  一直接收直到EOF

sh.recvrepeat(timeout = default)  持续接受直到EOF或timeout

---

*交互*

sh.interactive()  直接进行交互，相当于回到shell的模式，在取得shell之后使用

以上参考了JuH0n的这篇[文章]((https://www.jianshu.com/p/355e4badab50))

了解了大概之后就是……实践环节了

**目标只有一个：学会接收数据、显示数据和发送数据**

~~比个自己，辣鸡.jpg~~

假如我已经

`from pwn import *`

并且

`con = remote('116.85.48.103',5002)`

~~写这个就是为了解释下面的con是啥~~

0x01
----

先说说**recvall**

 作用：一直接收直到EOF，EOF，檔案結尾

当年看使用方法忽视了EOF，看名字直接以为就是读取全部内容的意思，还觉得这个好棒棒阿我`a = con.recvall()`然后`print a`岂不是就能把服务端发给我的东西显示出来了

~~然后就gg了~~

在python shell里面它是这样的
![](http://chuantu.biz/t6/296/1524767856x-1566661211.png)
在脚本里ta出来是这样的
![](http://chuantu.biz/t6/296/1524767984x-1566660859.png)

………………

后来反应过来才发现并没有文件………………

还专门去看了下[EOF](http://www.ruanyifeng.com/blog/2011/11/eof.html)…………

![](http://chuantu.biz/t6/296/1524768229x-1566661211.png)



0x02
---

看看还有啥能接收的

这里说最常用的两个


**sh.recvline(keepends=True)  接受一行数据，keepends为是否保留行尾的\n**

**sh.recvuntil("balabala",drop=fasle)  接受数据直到我们设置的标志出现**

一般用上面那个，下面那个用于我们要`提取服务端返回的一些信息`

举个例子

先mark一下我在用的这个端口收发什么信息

```html
Please enter mission key:
2acba569d223cf7d6e48dee88378288a
Please enter your Agent ID to secure communications:
1
23c9aca0b2db908252cd2f945f6d6f0ad343851c523e74c0f097d6f51d0c763fcc4847bc5e352f0315f08df6c7f75c1823169f86f2fe30372ab93ee429d7031ba4e385e73db5fee22c76e6a9fb1fb90036fd167d8f52c816a2e7c34e2ab35047
Please send some messages to be encrypted, 'quit' to exit:
2
ab54e1e13bdefa26933cccb253f1fd2d
Please send some messages to be encrypted, 'quit' to exit:
3
8d0a55c529c06c62c810eff18af70a7b
Please send some messages to be encrypted, 'quit' to exit:

```

大概就是
S：请输入mission key
C：……
S：请输入ID
C：……
S：密文
S：请输入加密信息
C：……
S：请输入加密信息
C：……
……


如果我们有这样的代码

```python
from pwn import *
mk = '2acba569d223cf7d6e48dee88378288a'
con = remote('116.85.48.103',5002)
a = con.recvline()
print 'receive:',a
print 'send:',mk
con.sendline(mk)
con.interactive()
```

就会出来这样的结果

```
root@kali:~/Desktop# python pwntool.py 
[+] Opening connection to 116.85.48.103 on port 5002: Done
receive: Please enter mission key:

send: 2acba569d223cf7d6e48dee88378288a
[*] Switching to interactive mode
Please enter your Agent ID to secure communications:
$  
```

这里服务端询问我们mission key，我们利用`sendline`成功发送了，然后使用`interactive`让我们自己继续和服务器端交互

由于它这次返回的内容没有我们要提取的内容，所以我们接收的时候用`recvline`就可以了

**注意，`recvline`每次只能读取一行，所以如果返回几行了而且你又要用`recvline`的话……就只能`recvline`多几次了**

惨烈程度大概就这样

代码：
```
from pwn import *
mk = '2acba569d223cf7d6e48dee88378288a'
con = remote('116.85.48.103',5002)
a = con.recvline()
print 'receive:',a
print 'send:',mk
con.sendline(mk)
con.sendlineafter('communications:','1')
#a con.recvuntil('
a = con.recvline()
print '2a:',a
a = con.recvline()
print '3a:',a
a = con.recvline()
print '4a',a
print 'fin'
con.interactive()
```
结果：
```html
root@kali:~/Desktop# python pwntool.py 
[+] Opening connection to 116.85.48.103 on port 5002: Done
receive: Please enter mission key:

send: 2acba569d223cf7d6e48dee88378288a
2a: 

3a: 17ad884d224664826a00a05c6e035adcf1b341194e840d3a0fc39bc049390db13949efa7afff686e4465037f58883949c62fd0ce7119ea6b052a02cf42e5a9f89563342f397bda8bf55cbfbaf35ab84ea4be3bcb80443640322785baa8c2cf85

4a Please send some messages to be encrypted, 'quit' to exit:

fin
[*] Switching to interactive mode
$  

```

所以还是`sendlineafter`大法好，`sendlineafter` ≈ `recvuntil` + `sendline` 下面会介绍

这里顺便提一下我踩过的一个坑

`recvline`和`sendlineafter`配合食用可能会引起食物中毒……

![](http://chuantu.biz/t6/296/1524769260x-1566661211.png)

大概就是……`recvline`把所有东西读取完之后，`sendlineafter`一直在等着receive `key:`吧……

~~我为什么当反面教材当得那么熟练阿~~

当然上面的`a = con.recvline()`+`con.sendline(mk)`其实可以直接用
`c.sendlineafter('key:', mk)`，参考了六星大佬强网杯WP中nextrsa的[脚本](https://github.com/sixstars/ctf/tree/master/2018/qiangwangbei)


然后，如果我们要提取key word的话， ~~虽然这个端口好像不需要但是懒得换一个了……~~

就假如我们要提取Please enter your Agent ID to secure communications:，我们返回id之后，服务端会返回：

```html
23c9aca0b2db908252cd2f945f6d6f0ad343851c523e74c0f097d6f51d0c763fcc4847bc5e352f0315f08df6c7f75c1823169f86f2fe30372ab93ee429d7031ba4e385e73db5fee22c76e6a9fb1fb90036fd167d8f52c816a2e7c34e2ab35047
Please send some messages to be encrypted, 'quit' to exit:
```
如果我们要提取"messages"这个单词
我们可以使用

```
from pwn import *
mk = '2acba569d223cf7d6e48dee88378288a'
con = remote('116.85.48.103',5002)
a = con.recvline()
con.sendline(mk)
con.sendlineafter('communications:','1')
con.recvuntil('some ')
a = con.recvline()[0:8]
print 'we_get:',a
con.interactive()
```

结果：

```htmlbars
root@kali:~/Desktop# python toolpwn.py 
[+] Opening connection to 116.85.48.103 on port 5002: Done
we_get: messages
[*] Switching to interactive mode
$  

```
在这里，我们采用`recvuntil`读取到`some` ，这时再用`recvline()`就会从message开始读，我们就能轻而易举地将我们需要的东西提取出来了。


综上，`学会接收数据、显示数据和发送数据`完成，溜了溜了






