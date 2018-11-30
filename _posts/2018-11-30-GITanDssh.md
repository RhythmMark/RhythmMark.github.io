---
layout: post
title: "GIT & ssh"
date: 2018-11-30
excerpt: "我也不知道这俩怎么在一起的，大概这就是传说中的拉郎配吧"
tags: [git,ssh,免密登陆]
feature: https://cdn-images-1.medium.com/max/1600/1*QoR3rxWIbnf5wmF_IuAHqQ.png
comments: true
---

# GIT & ssh


## git 命令

准备工作：

``git config --global user.email "你邮箱地址"``

``git config --global user.name "你的名字"``

开始参与项目：


克隆项目

``git clone 项目地址``

``cd 该项目的目录``

创建分支

``git branch 分支名``

转换分支

``git checkout 分支名``

然后做你想做的修改

改完之后添加修改进暂存区

``git add .``

其中`.`是当前目录的意思

提交更改

``git commit -m "提交信息"``

让远程的知道
``git push origin 分支名``

---

附：
``git status ``：查看状态

``git diff ``：查看修改

``git branch``：查看分支

``git checkout .``： 撤销本地修改（已 ``add/ commit ``的不适用）

``git log`` ：查看历史记录（commit）

``git reset --hard 版本号前几位``：撤销、回退

---

睡一觉醒来继续修改这个项目之前，先取回远程上的更新

``git pull origin master``

其中``master``是要取回更新的分支名

---


## ssh免密登陆

一般使用ssh，都是``ssh user@host``然后输入密码

当然现在我更常用的是``免密登陆``

### 0x01 查看（client端）公钥

``cat ~/.ssh/id_rsa.pub``

### 0x02  （在sever端）添加公钥

``vim ~/.ssh/authorized_keys``

把公钥追加上去即可，保存后，拥有该公钥的客户端就有登陆该服务器的权限了。

此时``ssh -p 端口 用户名@服务器域名或ip``即可登录服务器。

接下来是能让以后登录更方便的设置

###0x03

``vim ~/.ssh/config``

增加

```
Host 自取别名

User 同户名

HostName 服务器域名或ip

Port 端口号

IdentityFile ~/.ssh/id_rsa
```

以后要登陆服务器直接``ssh 自取别名``即可，美滋滋
