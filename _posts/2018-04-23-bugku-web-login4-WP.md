---
layout: post
title: "【CBC字节翻转】三文鱼都能看懂的bugku-web-login4-WP"
date: 2018-04-23
excerpt: "如题"
tags: [CBC 字节翻转攻击, bugku,web,Crypto,CTF,Write up,三文鱼]
feature: http://www.nsoad.com/upload/20161014/d6804a98376fedd714d6e578aa6c7e14.png
comments: true
---


# 三文鱼都能看懂的CBC字节翻转:D


------

**代码审计之前**

这是在[bugku](http://ctf.bugku.com/challenges)里web分类中的最后一道题。
打开就看到一个连接和一个hint，hint说是`CBC字节翻转攻击`。
 ![](http://chuantu.biz/t6/293/1524449476x-1566661211.png)

我们先用SourceLeakHacker扫一下，SourceLeakHacker是一款敏感目录扫描工具，敏感目录扫描是web~~狗~~手的常用姿势之一。
![](http://chuantu.biz/t6/293/1524481869x-1566661211.png)
 
看到那个绿色的200表示能够成功访问，这就是我们扫出来的敏感路径


我们这里要用到的是.index.php.swp这个文件

我们不用很麻烦就能通过[搜索引擎](https://www.google.com/)知道这个文件是非正常关闭vi编辑器时生成的。

我们访问这个url，就能成功下载这个文件。
![]( http://chuantu.biz/t6/293/1524481905x-1566661211.png)
这个文件是需要恢复的。恢复方法如下：
将文件拖入虚拟机，在文件所在的目录（下图的第一条指令）使用

`vi -r index.php.swp`

这条命令
![](http://chuantu.biz/t6/293/1524481976x-1566661211.png)
然后会出来这个样子的
![](http://chuantu.biz/t6/293/1524482000x-1566661211.png)

那它说Press ENTER or type command to continue就按个enter呗

然后就出来我们需要的代码了
 ![](http://chuantu.biz/t6/293/1524482024x-1566661211.png)
这时Esc进入命令模式~~其实不按也行，因为本来就在命令模式，这也是个人习惯吧~~

敲
`:w index.php`

把还原出来的php文件另存为 index.php
 ![](http://chuantu.biz/t6/293/1524482388x-1566661211.png)
然后它会说index.php成功保存了

再敲
`:q!`

退出编辑器

~~把生成的文件拖回Windows~~

然后就可以开始看代码了

------

**PHP代码审计进行时**

拔出来的代码如下

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Login Form</title>
<link href="static/css/style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="static/js/jquery.min.js"></script>
<script type="text/javascript">
$(document).ready(function() {
	$(".username").focus(function() {
		$(".user-icon").css("left","-48px");
	});
	$(".username").blur(function() {
		$(".user-icon").css("left","0px");
	});

	$(".password").focus(function() {
		$(".pass-icon").css("left","-48px");
	});
	$(".password").blur(function() {
		$(".pass-icon").css("left","0px");
	});
});
</script>
</head>

<?php
define("SECRET_KEY", file_get_contents('/root/key'));

define("METHOD", "aes-128-cbc");
session_start();

function get_random_iv(){
    $random_iv='';
    for($i=0;$i<16;$i++){
        $random_iv.=chr(rand(1,255));
    }
    return $random_iv;
}

function login($info){
    $iv = get_random_iv();
	#初始向量
    $plain = serialize($info);
	#info序列化后得到明文
    $cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
	#CBC模式下AES的加密明文
    $_SESSION['username'] = $info['username'];
    setcookie("iv", base64_encode($iv));
	#初始向量经过base64加密
    setcookie("cipher", base64_encode($cipher));
	#45行出来的密文再加一层base64加密
}

function check_login(){
    if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
        $cipher = base64_decode($_COOKIE['cipher']);
        $iv = base64_decode($_COOKIE["iv"]);
		#base64解密
        if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
			#aes解密
            $info = unserialize($plain) or die("<p>base64_decode('".base64_encode($plain)."') can't unserialize</p>");
			#判断是否能成功反序列化
            $_SESSION['username'] = $info['username'];
        }else{
            die("ERROR!");
        }
    }
}

function show_homepage(){
    if ($_SESSION["username"]==='admin'){
		#这里可以get flag
		#可见我们的session里的username必须要是admin
        echo '<p>Hello admin</p>';
        echo '<p>Flag is $flag</p>';
    }else{
        echo '<p>hello '.$_SESSION['username'].'</p>';
        echo '<p>Only admin can see flag</p>';
    }
    echo '<p><a href="loginout.php">Log out</a></p>';
}

if(isset($_POST['username']) && isset($_POST['password'])){
    $username = (string)$_POST['username'];
    $password = (string)$_POST['password'];
    if($username === 'admin'){
		#如果username是admin的话，就会显示下面这句话然后退出
        exit('<p>admin are not allowed to login</p>');
    }else{
        $info = array('username'=>$username,'password'=>$password);
        login($info);
        show_homepage();
    }
}else{
    if(isset($_SESSION["username"])){
		#如果password为空
        check_login();
        show_homepage();
    }else{
        echo '<body class="login-body">
                <div id="wrapper">
                    <div class="user-icon"></div>
                    <div class="pass-icon"></div>
                    <form name="login-form" class="login-form" action="" method="post">
                        <div class="header">
                        <h1>Login Form</h1>
                        <span>Fill out the form below to login to my super awesome imaginary control panel.</span>
                        </div>
                        <div class="content">
                        <input name="username" type="text" class="input username" value="Username" onfocus="this.value=\'\'" />
                        <input name="password" type="password" class="input password" value="Password" onfocus="this.value=\'\'" />
                        </div>
                        <div class="footer">
                        <input type="submit" name="submit" value="Login" class="button" />
                        </div>
                    </form>
                </div>
            </body>';
    }
}
?>
</html>

```

我个人习惯是先看flag在哪，然后看怎么才能到达这个地方，

~~但是某不愿意透露姓名的web大佬是习惯从入口开始看的，和我刚好相反。~~

~~（以下纯属个人做法，参考一下就好，想要更厉害的代码审计方法可以去py一下其他web大佬）~~

Ctrl+F搜flag
 ![](http://chuantu.biz/t6/293/1524482595x-1566661211.png)
看到在show_homepage()这个函数里，$_SESSION["username"]==='admin'的话我们就能get flag了

那么哪里用到show_homepage()呢？有两个地方

第一个是
 ![](http://chuantu.biz/t6/293/1524482636x-1566661211.png)
 此时username和password都有post，而且username不能为admin，那么经过login函数之后，就会运行到show_homepage()了。

我们看看login干了啥
 ![](http://chuantu.biz/t6/293/1524482701x-1566661211.png)

~~意思意思画个不规范的流程图~~
![](http://chuantu.biz/t6/293/1524482912x-1566661211.png)

这里我们注意到最后一步，
```$_SESSION['username'] = $info['username']```

而根据info的定义赋值可知，`$info['username']`是我们传进进去的账户名的值。

但是由第93-95行代码可知，如果我们穿进去的账户名值为username，就会在一开始直接返回admin are not allowed to login然后退出，所以此路不通。

幸好用到show_homepage()的还有另一个地方。
 ![](http://chuantu.biz/t6/293/1524482931x-1566661211.png)
 首先要不进入刚刚的那个if，就是不满足
```set($_POST['username']) && isset($_POST['password'])```
然后，要有$_SESSION["username"]在

然后我们看看check_login()干了啥
![](http://chuantu.biz/t6/293/1524483429x-1566661211.png)
其实就是相当于把login逆了过来而已。

在正常情况下，如果我们正正经经地post一个账户名和口令字，这个网页就会把你post的东西经过login那一系列的变化，用cookie保存下来，然后下次我们不需要再post东西了，凭借cookie，网站通过check_login得到我们post过得账户名和口令字，就能知道我们的身份。

这样经过check_login函数之后，```$_SESSION['username']```就还是我们最开始post的那个username。

但我们是正经人吗？我们是要~~搞事~~get flag的人，所以我们就要想如何把`$_SESSION['username']`变成`admin`，

即使我们最开始post的可能是admi2，

但是它经过了AES加密和解密阿，这就有得搞了阿。

这里就要用到hint里面提到的CBC字节翻转攻击

攻击的point就在·check_login()·的解密过程里。

~~PHP代码审计终于结束，可喜可贺可喜可贺~~

什么是加密模式就不多说了，下面直接


------

**CBC加密模式介绍**
![](http://chuantu.biz/t6/293/1524483577x-1566661211.png)
CBC它，就是每个明文块先与前一个密文块进行异或后，再进行加密
![](http://chuantu.biz/t6/293/1524483624x-1566661211.png)
详细一点表达加密过程，就是

当

P是明文，C是密文，下标表示第几组EK是加密，DK是解密，IV是初始向量，Z就是个用来辅助的

另

Z1 = P1 ⊕ IV

Z2 = P2 ⊕ C1

Z3 = P3 ⊕ C2

…

Zi = Pi ⊕ Ci-1

…
然后密文就是

C0 = IV

C1 = EK(Z1)

C2 = EK(Z2)

…

Ci = EK(Zi)

…

以上都是为了更好地理解

**加密  ↓**

Ci = EK(Pi⊕Ci-1)

所以

Pi ⊕ Ci-1 = DK(Ci)

Pi = DK(Ci) ⊕ Ci-1   **<-解密**

~~word里面辛辛苦苦做下标，改成.md一朝回到解放前~~

所以，我们可以通过修改Ci-1来达到修改Pi的目的

我们先来看一下CBC字节翻转攻击是怎么做的
 
这里直接引用[这里](http://cb.drops.wiki/drops/tips-7828.html) 提到的一个例子

~~刚发现链接好像打不开了？？？？~~

___

【复制粘贴开始】


比方说，我们有这样的明文序列：  

a:2:{s:4:"name";s:6:"sdsdsd";s:8:"greeting";s:20:"echo 'Hello sdsdsd!'";}

我们的目标是将“s:6”当中的数字6转换成数字“7”。我们需要做的第一件事就是把明文分成16个字节的块：

•	Block 1:a:2:{s:4:"name";

•	Block 2:s:6:"sdsdsd";s:8

•	Block 3::"greeting";s:20

•	Block 4::"echo 'Hello sd

•	Block 5:sdsd!'";}

因此，我们的目标字符位于块2，这意味着我们需要改变块1的密文来改变第二块的明文。

有一条经验法则是（注：结合上面的说明图可以得到），你在密文中改变的字节，只会影响到在下一明文当中，具有相同偏移量的字节。所以我们目标的偏移量是2：

•	[0] = s

•	1 = :

•	2 =6

因此我们要改变在第一个密文块当中，偏移量是2的字节。正如你在下面的代码当中看到的，在第2行我们得到了整个数据的密文，然后在第3行中，我们改变块1中偏移量为2的字节，最后我们再调用解密函数。

1.	```$v = "a:2:{s:4:"name";s:6:"sdsdsd";s:8:"greeting";s:20:"echo 'Hello sdsdsd!'";}";```

2.	```$enc = @encrypt($v);```

3.	```$enc[2] = chr(ord($enc[2]) ^ ord("6") ^ ord ("7"));```

4.	```$b = @decrypt($enc);```

>

运行这段代码后，我们可以将数字6变为7：

但是我们在第3行中，是如何改变字节成为我们想要的值呢？

基于上述的解密过程，我们知道有，A = Decrypt(Ciphertext)与B = Ciphertext-N-1异或后最终得到C = 6。等价于：

C = A XOR B

所以，我们唯一不知道的值就是A（注：对于B，C来说）（block cipher decryption）;借由XOR，我们可以很轻易地得到A的值：

A = B XOR C

最后，A XOR B XOR C等于0。有了这个公式，我们可以在XOR运算的末尾处设置我们自己的值，就像这样：

A XOR B XOR C XOR "7"会在块2的明文当中，偏移量为2的字节处得到7。

【复制粘贴结束】

___


然后回到我们这一题。

我们的明文序列是：

`a:2:{s:8:"username";s:5:"admi2";s:8:"password";s:8:"Password";}`


wait a minute ……这个明文序列怎么来的?

这是因为，我们知道：

```$info = array('username'=>$username,'password'=>$password);```

我们可以用

```php
<?php
$info = array('username'=>'admi2','password'=>'Password');
echo serialize($info);
?>
```

开个phpstudy localhost访问一下就能得到上面那个明文序列

然后

我们也分个块

```
a:2:{s:8:"userna
me";s:5:"admi2";
s:8:"password";s
:8:"Password";}
```

我们要改的是admi2中的’2’，也就是第二列的第13个

~~插一段黑历史
请不要像我一样数的时候没数到python框住字符串的单引号以为第二行的"就是结束谢谢~~

![](http://chuantu.biz/t6/293/1524484373x-1566661211.png)

~~get 不到？我当年是从上图第三行那里数出来'2'在倒数第二个也就是排15的……~~

按照CBC字节翻转攻击的套路，我们要修改的是上一个分组对应位置的密文

就是下面会放的脚本中的代码：

```bs_de[13]=chr(ord(bs_de[13]) ^ ord('2') ^ ord('n'))```

也就是，如果crypto是我们那个明文序列经过aes加密后的密文

只要我们令

**crypto[13] = crypto[13] ⊕ ‘2’ ⊕ ‘n’**

即，把第一个分组的第13个字符（因为我们要改的是第二个分组中的第13个字符），变成

**crypto[13] ⊕ ‘2’ ⊕ ‘n’**

其实就是: `密文 ⊕ 我们要改掉的 ⊕ 我们要改成的`

我们看看解密的时候会发生什么？

我们知道，解密是Pi = DK(Ci) ⊕ Ci-1

我们把crypto[13]，也就是上式的Ci-1改了

当i= 2 时

Pi = DK(Ci) ⊕ Ci-1 = DK(Ci) ⊕ crypto[13] ⊕ ‘2’ ⊕ ‘n’

而我们又有

Pi = DK(Ci) ⊕ Ci-1           

Pi ⊕ DK(Ci) ⊕ Ci-1 = 0

_异或其实就是二进制里面的加法，而且相同的相加为零，这式子相当于两边同时加Pi_

DK(Ci) ⊕ Ci-1 ⊕ Pi = 0

DK(Ci)[13] ⊕ Ci-1 [13]⊕ Pi [13]= 0

DK(Ci) ⊕ crypto[13] ⊕ ‘2’ = 0

DK(Ci) ⊕ crypto[13] ⊕ ‘2’ ⊕ ‘n’ = ‘n’

Pi = DK(Ci) ⊕ Ci-1 = DK(Ci) ⊕ crypto[13] ⊕ ‘2’ ⊕ ‘n’ = ‘n’

**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;↑这里check_login在解密的时候就这么做，和DK(Ci)异或**

**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;↑这是我们修改了的密文**

**↑这是check_login 解密之后产生的明文**

综上，只要我们把第一组密文改一改，就能让它解密之后第二组的明文产生变化。

我们再回到这道题

Login函数中	| | |	 
---- |:---|---
iv和序列化后的Info (usn,psd)	| | |	
↓	|->	|aes加密前的明文
aes-128-cbc||		
↓	|->	|aes加密后的密文
base64	||	
↓		||
赋值给cookie	| |	
…		||		

check_login中 | | |
---- |:---|---
从cookie里读入'cipher'和'iv'&nbsp;&nbsp;		 |||
↓		||
base64解码		||
↓|	->	|aes解密前的密文
aes解密		||
↓	|->|	aes解密后的明文
反序列化		||
…		||


我们的CBC字符翻转攻击就是在上表倒数第四列用的。

直接上脚本

```python
# -*- coding:utf-8 -*-

import base64
from urllib import unquote
from urllib import quote_plus

bs = 'J67IvH4OY9t6QfcCP4Mp88bRfPKdsYszlev3LNbgPQ872VR633trbWfCqhcDYm6c3Eysp36W2SFkx4CPBX9nDQ%3D%3D'
#密文cipher，从Chrome的插件EditThisCookie可以很轻松get到
bs = unquote(bs)
#url解码
bs_de = base64.b64decode(bs)
#base64解码

ch = chr(ord(bs_de[13]) ^ ord('2') ^ ord('n'))
bs_de=bs_de[0:13]+ch+bs_de[14::]
#其实就是bs_de[13]=chr(ord(bs_de[13]) ^ ord('2') ^ ord('n'))
#因为python里面字符串不可变，即你直接bs_de = 'a'这样会报错

rs = base64.b64encode(bs_de)
#print rs
print quote_plus(rs)

```

我们在最开始的页面，第一行填admi2，第二行碰都不要碰（它会自动帮你填充Password，如果你点击了一下Password就~~gg~~为空了）

进去之后使用Chrome的插件EditThisCookie，把cipher的值赋给脚本中的bs
  ![](http://chuantu.biz/t6/293/1524487870x-1566661211.png)
运行后，脚本返回修改了第一个密文分组的值的密文，当然它还经过了base64编码和urlencode
 ![](http://chuantu.biz/t6/293/1524487923x-1566661211.png)
我们把这堆东西贴到cipher那，然后按
![](http://chuantu.biz/t6/293/1524487979x-1566661211.png)
绿色这个勾保存，然后在回车栏按enter

注意：不要按刷新，因为刷新的话会~~gg~~重新提交表格，也就是之前post的username和password会重新提交，password不为空我们就又进去login而进不去check_login了，而我们直接回车栏enter是不会post东西的，但是cookie已经被我们改了。

然后它返回个错误，说反序列化失败
 ![](http://chuantu.biz/t6/293/1524488038x-1566661211.png)
这是当然的，因为我们把第一组的密文改了，第一组解密之后又不是原来的那个字符串，当然反序列化失败。

我们把这串东西base64解密一下看看
 ![](http://chuantu.biz/t6/293/1524488056x-1566661211.png)
我们看到，我们已经成功地把admi2变成admin了

所以下一步我们就要用相同的套路，来复原第一个密文分组，也就是初始向量。

还记得我之前提到的吗？

把上一分组对应的密文 变成 密文 ⊕ 我们要改掉的 ⊕ 我们要改成的

我还说过，密文是什么？
C0 = IV
C1 = EK(Z1)
C2 = EK(Z2)
所以我们要第一个分组的明文，当然就要对C0 = IV下手了

原理和第一关一样，直接我们第二个脚本
```python
# -*- coding:utf-8 -*-

import base64
from urllib import unquote
from urllib import quote_plus

mingwen_de='nj7W9vwn0gxyOdX3xUN/lG1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjg6IlBhc3N3b3JkIjt9'
#base64_decode('这里面的') can't unserialize
mingwen = base64.b64decode(mingwen_de)
print mingwen

iv = 'cFDYuzPtN1Q5ETd1E7s1Zw%3D%3D'
#此时cookie里的iv
iv = unquote(iv)
iv_de = base64.b64decode(iv)
new = 'a:2:{s:8:"userna'
for i in range(16):
    iv_de = iv_de[:i] + chr(ord(iv_de[i]) ^ ord(mingwen[i]) ^ ord(new[i])) + iv_de[i+1:]
#iv_de[i]=chr(ord(iv_de[i]) ^ ord(mingwen[i]) ^ ord(new[i]))

print(base64.b64encode(iv_de))
#用这个结果把原来的iv换掉

```

主要就是
```python
for i in range(16):
    iv_de = iv_de[:i] + chr(ord(iv_de[i]) ^ ord(mingwen[i]) ^ ord(new[i])) + iv_de[i+1:]

```

也就是

`iv_de[i]=chr(ord(iv_de[i]) ^ ord(mingwen[i]) ^ ord(new[i]))`

i遍历第一个分组的所有字符

搞这么复杂的原因在cbc1.py的注释有提到，因为python不给我们直接改字符串

这其中，iv_de就是IV，mingwen就是当前它解密出来的明文，也就是我们要改的，new是正确的明文，就是我们想要改变的

这一点满足我之前说的

**密文 = 密文 ⊕ 我们要改掉的 ⊕ 我们要改成的**

这个脚本运行出来的东西就是我们改变后的IV的密文，再base64一下urlencode一下，然后把当前的IV换成这个，然后刷新或者地址栏回车都可以（因为上一次操作并没有携带post的内容），然后我们就能get flag了
 
 
------

**最后再啰嗦一次，这道题怎么做呢？**

打开bugku

~~然后SourceLeakHacker 把index.php.swp扫出来~~

~~然后vi -r index.php.swp 还原出php文件~~

~~然后代码审计~~

~~然后~~在登录页面的第一个框输入admi2，第二个框不要碰

然后我们打开EditThisCookie，把cipher的值赋给脚本cbc1.py中的bs，运行

把运行结果赋值给cookie中的cipher，地址栏按回车

把页面出现的base64_decode('这里面的') can't unserialize，单引号中的那个字符串，赋值给脚本cbc2.py中的mingwen_de

打开EditThisCookie，把iv的值赋给脚本cbc2.py中的iv

用运行脚本后得到的第二个字符串，替换掉cookie里的iv

刷新，get flag

------


**最后,欢迎交流 :D**

