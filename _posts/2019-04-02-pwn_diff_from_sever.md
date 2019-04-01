---
layout: post
title: " pwn题-与服务器不同的一万种可能 "
date: 2019-04-02
excerpt: "……话说我这些blog看不懂是正常的因为一些问题我自己也没怎么弄懂有空会整理一下的（有生之年，我保证）"
tags: [pwn]
feature:  https://p0.ssl.qhimg.com/t01a969a8d998ad5508.png
comments: true
---

# pwn题-与服务器不同的一万种可能


## 0x0 

↑哇好可爱（×）

libc不同。感觉这个最常见。

## =x=

操作系统不同。

当年做一道32x的题的时候，同样的脚本能pwn服务器不能pwn本机。

服务器是64位的，而我的虚拟机是32位的。

原因是exp里用到了write函数，

``write(fd,*buf,len)``

而``*buf+len``所在地址在64x有在32位没有（还是不可写之类的，whatever）……

## QwQ

有空再补充。

（偶尔写一下这么短的blog也是爽）
