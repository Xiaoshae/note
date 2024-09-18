# php



## 基本语法

###  标记

PHP 的起始标记和结束标记分别是 `<?php` 和 `?>`，如果最后一个 PHP 段后无非PHP内容，则可以省略结束标志。

PHP 标记的简写形式为 `<?` 和 `?>`，在一些PHP中默认启用，可以通过 short_open_tag php.ini 直接禁用，或者在 PHP 安装时使用  **--disable-short-tags** 配置。

PHP 有一个 echo 标记简写 `<?=`， 它是更完整的 `<?php echo` 的简写形式，此方法在官方文档说明中无法被禁用。



#### 示例 #1 最后PHP段标记可以省略

```php
<?php echo "the is my website"; ?>
<?php echo "the is my website";
```



#### 示例2 #1 使用PHP短标记：

```php
<?php echo "the is my website"; ?>
<?    echo "the is my website"; ?>
```



#### 示例 #3 echo简写标记

```php
<?php echo "the is my website"; ?>
<?=        "the is my website"; ?>
```



### 从 HTML 中分离

PHP 嵌入到 HTML 文档，开始和结束标记之外的内容会被忽略。

```php+HTML
<p>This is going to be ignored by PHP and displayed by the browser.</p>
<?php echo 'While this is going to be parsed.'; ?>
<p>This will also be ignored by PHP and displayed by the browser.</p>
```



#### 示例 #1 使用条件的高级分离术

PHP 将跳过条件语句未达成的段落，即使该段落位于 PHP 开始和结束标记之外。

要输出大段文本时，跳出 PHP 解析模式通常比将文本通过 echo 或 print 输出更有效率。

```
<?php if ($expression == true): ?>
  This will show if the expression is true.
<?php else: ?>
  Otherwise this will show.
<?php endif; ?>
```



### 指令分隔符

PHP 需要在每个语句后用分号结束指令，PHP 代码中的结束标记隐含表示了一个分号，最后一行可以不用分号结束。

如果 PHP 代码段没有结束标记，则需要使用分号结束。

```php
<?php echo "the is my website"; ?>
<?php echo "the is my website"  ?>
<?php echo "the is my website";
```



### 注释

PHP 支持 C、C++ 的注释风格，以及 uinx shell 的单行注释风格。

```php
<?php
    echo 'This is a test'; // 这是单行 c++ 样式注释
    /* 这是一条多行注释
       另一行也是注释 */
    echo 'This is yet another test';
    echo 'One Final Test'; # 这是单行 shell 风格的注释
?>
```



C 风格的注释在碰到第一个 `*/` 时结束。要确保不要嵌套 C 风格的注释。试图注释掉一大块代码时很容易出现该错误。

```php
<?php
 /*
    echo 'This is a test'; /* 这个注释会引发问题 */
 */
?>
```



## 类型

PHP 是动态类型语言，不需要指定变量的类型，在运行时确定。可以使用**类型声明**对语言的一些方面进行类型静态化。

如果使用的表达式/变量不支持该操作，PHP 将尝试将该值类型转换为操作支持的类型。（决于使用该值的上下文）

### null

null 类型是 PHP 的原子类型（unit type），null 类型只有一个值，就是**不区分大小写的常量** null。

未定义和 unset() 的变量都将解析为值 null。



使用 (unset) $var 将一个变量转换为 null 将不会删除该变量或 unset 其值。仅是返回 null 值而已。

> **PHP 7.2.0 起废弃，PHP 8.0.0 起被移除**



注意：空数组通过非严格相等的 '==' 比较转换为 null。如果有可能获得空数组，请使用 is_null() 或 '==='。

```php
$a = array();

$a == null  <== return true
$a === null < == return false
is_null($a) <== return false
```



### Boolean 布尔类型

bool 仅有两个值，用于表达真（truth）值，使用常量 true 或 false，不区分大小写。

```php
<?php
$foo = True; // 设置 $foo 为 TRUE
?>
```



通常**运算符**所返回的 **bool 值**结果会被传递给**控制流程**。

```php
<?php
// == 是一个操作符，它检测两个变量是否相等，并返回一个布尔值
if ($action == "show_version") {
    echo "The version is 1.23";
}

// 这样做是不必要的...
if ($show_separators == TRUE) {
    echo "<hr>\n";
}

// ...因为可以使用下面这种简单的方式：
if ($show_separators) {
    echo "<hr>\n";
}
?>
```



#### 转换为布尔值 

要明确地将值转换成 bool，可以用 (bool) 强制转换。通常这不是必需的，因为值在逻辑上下文中使用将会自动解释为 bool 类型的值。

当转换为 bool 时，以下值被认为是 false：

- 布尔值 false 本身
- 整型值 0（零）
- 浮点型值 0.0（零）-0.0（零）
- 空字符串 ""，以及字符串 "0"
- 不包括任何元素的数组
- 原子类型 NULL（包括尚未赋值的变量）
- 内部对象的强制转换行为重载为 bool。例如：由不带属性的空元素创建的 SimpleXML 对象。

所有其它值都被认为是 true（包括 资源 和 NAN）。





### Integer 整型

int 是集合 ℤ = {..., -2, -1, 0, 1, 2, ...} 中的某个数。



Int 可以使用十进制，十六进制，八进制或二进制表示，前面可以加上可选的符号（- 或者 +）。 

```php
$a = 1234; // 十进制数
$a = +1234; // 十进制数
$a = -1234; // 十进制数
```



- 二进制表达，数字前必须加上 `0b`。
- 八进制表达，数字前必须加上 0（零）。
- 十六进制表达，数字前必须加上 0x。

```php
$a = 0b11111111; // 二进制数字 (等于十进制 255)
$a = 0123; // 八进制数 (等于十进制 83)
$a = 0x1A; // 十六进制数 (等于十进制 26)
```



PHP 8.1.0 起，八进制表达也可以在前面加上 `0o` 或者 `0O`。

```php
$a = 0o123; // 八进制数 (PHP 8.1.0 起)
```



从 PHP 7.4.0 开始，整型数值可能会包含下划线 (_)，为了更好的阅读体验，这些下划线在展示的时候，会被 PHP 过滤掉。

```php
$a = 1_234_567; // 整型数值 (PHP 7.4.0 以后)
```



#### 长度

整型数 int 的字长和平台有关，在32位平台最大值是大约二十亿（有符号），在64 位平台下的最大值通常是大约 9E18。

PHP 不支持无符号的 int，int 值的**字长**可以用常量 **PHP_INT_SIZE**来表示， **最大值**可以用常量 **PHP_INT_MAX** 来表示， **最小值**可以用常量 **PHP_INT_MIN** 表示。



##### 32 位整数溢出

如果给定的一个数超出了 int 的范围，将会被解释为 float。同样如果执行的运算结果超出了 int 范围，也会返回 float。

```php
<?php
$large_number = 2147483647;
var_dump($large_number);                     // int(2147483647)

$large_number = 2147483648;
var_dump($large_number);                     // float(2147483648)

$million = 1000000;
$large_number =  50000 * $million;
var_dump($large_number);                     // float(50000000000)
?>
```



##### 64 位整数溢出

```php
<?php
$large_number = 9223372036854775807;
var_dump($large_number);                     // int(9223372036854775807)

$large_number = 9223372036854775808;
var_dump($large_number);                     // float(9.2233720368548E+18)

$million = 1000000;
$large_number =  50000000000000 * $million;
var_dump($large_number);                     // float(5.0E+19)
?>
```



#### 计算

PHP 中 1/2 产生出 float 0.5， 值可以舍弃小数部分，强制转换为 int，或者使用 round() 函数可以更好地进行四舍五入。

```php
<?php
var_dump(25/7);         // float(3.5714285714286) 
var_dump((int) (25/7)); // int(3)
var_dump(round(25/7));  // float(4) 
?>
```



#### 转换为整型

用 (int) 或 (integer) 强制转换整型，

##### 从布尔值转换

false 将产生出 0（零），true 将产生出 1（壹）。

##### 从浮点型转换

当从浮点数 float 转换成整数 int时，将向零取整。

##### 从字符串转换

如果 string 是 numeric 或者前导数字， 则将它解析为相应的 int 值，否则将转换为零（0）。

##### 从 NULL 转换

null 会转换为零（0）。

##### 从其它类型转换

> **警告**：没有定义从其它类型转换为 int 的行为。 不要依赖任何现有的行为，因为它会未加通知地改变。



### Float 浮点型

浮点型（也叫浮点数 float，双精度数 double 或实数 real）可以用以下任一语法定义：

```php
<?php
$a = 1.234; 
$b = 1.2e3; 
$c = 7E-10;
$d = 1_234.567; // 从 PHP 7.4.0 开始支持
?>
```

浮点数的字长和平台相关，尽管通常最大值是 1.8e308 并具有 14 位十进制数字的精度（64 位 IEEE 格式）。

永远不要相信浮点数结果精确到了最后一位，也永远不要比较两个浮点数是否相等。如果确实需要更高的精度，应该使用任意精度数学函数或者 gmp 函数。



#### 从 string 转换

如果 string 是 **numeric**(数字字符串) 或者前导数字， 则将它解析为相应的 float 值，否则将转换为零（0）。



#### 从其他类型转换

对于其它类型的值，其情况类似于先将值转换成 int，然后再转换成 float。 



#### 比较浮点数

由于内部表达方式的原因，比较两个浮点数是否相等是有问题的，不过还是有迂回的方法来比较浮点数值的。

$a 和 $b 在小数点后五位精度内都是相等的。

```php
<?php
$a = 1.23456789;
$b = 1.23456780;
$epsilon = 0.00001;

if(abs($a-$b) < $epsilon) {
    echo "true";
}
?>
```



#### NaN

某些数学运算会产生一个由常量 **`NAN`** 所代表的结果。此结果代表着一个在浮点数运算中未定义或不可表述的值。任何拿此值与其它任何值（除了 **`true`**）进行的松散或严格比较的结果都是 **`false`**。

由于 **`NAN`** 代表着任何不同值，不应拿 **`NAN`** 去和其它值进行比较，包括其自身，应该用 is_nan() 来检查。



### String 字符串

一个字符串 string 就是由一系列的字符组成，其中每个字符等同于一个字节。这意味着 PHP 只能支持 256 的字符集，因此不支持 Unicode 。



一个字符串可以用 4 种方式表达：

- 单引号
- 双引号
- heredoc 语法结构
- nowdoc 语法结构





#### 单引号

定义一个字符串的最简单的方法是用单引号把它包围起来（字符 `'`）。

- 要表达一个单引号自身，需在它的前面加个反斜线（`\`）来转义。
- 要表达一个反斜线自身，则用两个反斜线（`\\`）。

其它任何方式的反斜线都会被当成反斜线本身：也就是说如果想使用其它转义序列例如 `\r` 或者 `\n`，并不代表任何特殊含义，就单纯是这两个字符本身。



> 注意: 不像双引号和 heredoc 语法结构，在单引号字符串中的变量和特殊字符的转义序列将不会被替换。

```php
<?php
echo 'this is a simple string';

// 可以录入多行
echo 'You can also have embedded newlines in
strings this way as it is
okay to do';

// 输出： Arnold once said: "I'll be back"
echo 'Arnold once said: "I\'ll be back"';

// 输出： You deleted C:\*.*?
echo 'You deleted C:\\*.*?';

// 输出： You deleted C:\*.*?
echo 'You deleted C:\*.*?';

// 输出： This will not expand: \n a newline
echo 'This will not expand: \n a newline';

// 输出： Variables do not $expand $either
echo 'Variables do not $expand $either';
?>
```



#### 双引号

如果字符串是包围在双引号（"）中， PHP 将对以下特殊的字符进行解析：

| 序列                 | 含义                                                         |
| :------------------- | :----------------------------------------------------------- |
| `\n`                 | 换行（ASCII 字符集中的 LF 或 0x0A (10)）                     |
| `\r`                 | 回车（ASCII 字符集中的 CR 或 0x0D (13)）                     |
| `\t`                 | 水平制表符（ASCII 字符集中的 HT 或 0x09 (9)）                |
| `\v`                 | 垂直制表符（ASCII 字符集中的 VT 或 0x0B (11)）               |
| `\e`                 | Escape（ASCII 字符集中的 ESC 或 0x1B (27)）                  |
| `\f`                 | 换页（ASCII 字符集中的 FF 或 0x0C (12)）                     |
| `\\`                 | 反斜线                                                       |
| `\$`                 | 美元标记                                                     |
| `\"`                 | 双引号                                                       |
| `\[0-7]{1,3}`        | 八进制：匹配正则表达式序列 `[0-7]{1,3}` 的是八进制表示法的字符序列（比如 `"\101" === "A"`），会静默溢出以适应一个字节（例如 `"\400" === "\000"`） |
| `\x[0-9A-Fa-f]{1,2}` | 十六进制：匹配正则表达式序列 `[0-9A-Fa-f]{1,2}` 的是十六进制表示法的一个字符（比如 `"\x41" === "A"`） |
| `\u{[0-9A-Fa-f]+}`   | Unicode：匹配正则表达式 `[0-9A-Fa-f]+` 的字符序列是 unicode 码位，该码位能作为 UTF-8 的表达方式输出字符串。序列中必须包含大括号。例如 `"\u{41}" === "A"` |

和单引号字符串一样，转义任何其它字符都会导致反斜线被显示出来。

用双引号定义的字符串最重要的特征是变量会被解析，详见变量解析。



#### Heredoc 结构

第三种表达字符串的方法是用 heredoc 句法结构：<<<。在该运算符之后要提供一个标识符，然后换行。接下来是字符串 string 本身，最后要用前面定义的标识符作为结束标志。

```php
<?php
echo <<<END
xiaoshae
END;
```



结束标识符可以使用空格或制表符（tab）缩进，此时文档字符串会删除所有缩进。 在 PHP 7.3.0 之前的版本中，结束时所引用的标识符必须在该行的第一列。（**标识符要遵守命名规则**）



**示例 #1 PHP 7.3.0 之后的基础 Heredoc 示例**

```php
<?php
// 无缩进
echo <<<END
      a
     b
    c
\n
END;
// 4 空格缩进
echo <<<END
      a
     b
    c
    END;
```

以上示例在 PHP 7.3 中的输出：

```
      a
     b
    c
  a
 b
c
```



如果结束标识符的缩进超过内容的任何一行的缩进，则将抛出 ParseError 异常：

**示例 #2 结束标识符的缩进不能超过正文的任何一行**

```php
<?php
echo <<<END
  a
 b
c
   END;
```

以上示例在 PHP 7.3 中的输出：

```
PHP Parse error:  Invalid body indentation level (expecting an indentation level of at least 3) in example.php on line 4
```



制表符也可以缩进结束标识符，但是，关于缩进结束标识符和内容， 制表符和空格不能混合使用。如果使用则会抛出 ParseError 异常。

存在这些空白限制，是因为混合制表符和空格来缩进不利于易读性。

```php
<?php
// 以下所有代码都不起作用。
// 正文（空格）和结束标记（制表符），不同的缩进
{
    echo <<<END
     a
        END;
}
// 在正文中混合空格和制表符
{
    echo <<<END
        a
     END;
}
// 在结束标记中混合空格和制表符
{
    echo <<<END
          a
         END;
}
```

**示例 #3 内容（空白）和结束标识符的不同缩进**

```php
<?php
// 以下所有代码都不起作用。
// 正文（空格）和结束标记（制表符），不同的缩进
{
    echo <<<END
     a
        END;
}
// 在正文中混合空格和制表符
{
    echo <<<END
        a
     END;
}
// 在结束标记中混合空格和制表符
{
    echo <<<END
          a
         END;
}
```



内容字符串的结束标识符后面不需要跟分号或者换行符。 例如，从 PHP 7.3.0 开始允许以下代码：

**示例 #4 在结束标识符后继续表达式**

```php
<?php
$values = [<<<END
a
  b
    c
END, 'd e f'];
var_dump($values);
```

以上示例在 PHP 7.3 中的输出：

```
array(2) {
  [0] =>
  string(11) "a
  b
    c"
  [1] =>
  string(5) "d e f"
}
```



#### nowdoc 结构

Nowdoc 结构中不进行解析操作，适合用于嵌入 PHP 代码或其它大段文本而无需对其中的特殊字符进行转义。

一个 nowdoc 结构也用和 heredocs 结构一样的标记 `<<<`， 但是跟在后面的标识符要用单引号括起来，即 `<<<'EOT'`。Heredoc 结构的所有规则也同样适用于 nowdoc 结构，尤其是结束标识符的规则。



**示例 #12 Nowdoc 结构字符串示例**

```php
<?php
echo <<<'EOD'
Example of string spanning multiple lines
using nowdoc syntax. Backslashes are always treated literally,
e.g. \\ and \'.
EOD;
```

以上示例会输出：

```
Example of string spanning multiple lines
using nowdoc syntax. Backslashes are always treated literally,
e.g. \\ and \'.
```



**示例 #13 含变量引用的 Nowdoc 字符串示例**

```php
<?php

/* 含有变量的更复杂的示例 */
class foo
{
    public $foo;
    public $bar;

    function __construct()
    {
        $this->foo = 'Foo';
        $this->bar = array('Bar1', 'Bar2', 'Bar3');
    }
}

$foo = new foo();
$name = 'MyName';

echo <<<'EOT'
My name is "$name". I am printing some $foo->foo.
Now, I am printing some {$foo->bar[1]}.
This should not print a capital 'A': \x41
EOT;
?>
```

以上示例会输出：

```
My name is "$name". I am printing some $foo->foo.
Now, I am printing some {$foo->bar[1]}.
This should not print a capital 'A': \x41
```



#### 数字字符串

如果一个 PHP **string** 可以被解释为 **int** 或 **float** 类型，则它被视为数字字符串。



**在数字上下文中使用的字符串**

当一个 string 需要被当作一个数字计算时，（例如：算术运算， int 类型声明等)，则采取以下步骤来确定结果：

1. 如果 string 是数字，当 string 是整数字符串并且符合 int 类型的范围限制（即是 PHP_INT_MAX 定义的值），则解析为 int ，否则解析为 float 。
2. 如果上下文允许前导数字和一个 string，如果 string 的前导部分是整数数字字符串且符合 int 类型限制（由 PHP_INT_MAX 定义），则解析为 int ，否则解析为 float 。 此外，还会导致 E_WARNING 级别的错误。
3. 如果 string 不是数字，则会抛出一个 TypeError 的异常。



**注意**:

任何包含字母 `E` 周围是数字的字符串都将视为以科学计数法表示的数字。这会产生意想不到的效果。

```php
var_dump("0D1" == "000"); // false, "0D1" 不是科学计数法
```

这一行中，`"0D1"` 不是科学计数法，因为科学计数法使用的是字母 `E` 而不是 `D`。因此，这个字符串只是普通的字符串 `"0D1"`，而不是一个数学上的表示。当它与 `"000"` 进行比较时，由于它们在字符上不匹配，所以结果是 `false`。



```php
var_dump("0E1" == "000"); // true, "0E1" is 0 * (10 ^ 1), or 0
```

这一行中，`"0E1"` 是有效的科学计数法，表示 `0 * 10^1`，即0。当它与 `"000"` 比较时，虽然一个是数字0，另一个是字符串 `"000"`，但在进行 `==` 比较时，PHP 会尝试将字符串转换成数字来进行比较。因此，`"000"` 被解释为数字0，两者相等，结果为 `true`。



```php
var_dump("2E1" == "020"); // true, "2E1" is 2 * (10 ^ 1), or 20
```

这一行中，`"2E1"` 同样是有效的科学计数法，表示 `2 * 10^1`，即20。当它与 `"020"` 比较时，字符串 `"020"` 被解释为数字20，所以 `20 == 20`，结果为 `true`。



**PHP 8.0.0 之前的行为**

在 PHP 8.0.0 之前， 只有在前导空格的时候，**string** 才被认为是数字；如果它有尾随空格，则该字符串被视为是前导数字。

在 PHP 8.0.0 之前，当在数字上下文中使用字符串时，它将执行与上述相同的步骤，但有以下区别：

- 使用前导数字字符串将导致 **E_NOTICE** 而不是 **E_WARNING** 错误。
- 如果字符串不是数字，则会导致 **E_WARNING** 错误并返回 0 。

在 PHP 7.1.0 之前，则既不会导致 **E_NOTICE**，也不会导致 **E_WARNING**。

```php
<?php
$foo = 1 + "10.5";                // $foo 是 float (11.5)
$foo = 1 + "-1.3e3";              // $foo 是 float (-1299)
$foo = 1 + "bob-1.3e3";           // PHP 8.0.0 起产生 TypeError；在此之前 $foo 是 integer (1)
$foo = 1 + "bob3";                // PHP 8.0.0 起产生 TypeError；在此之前 $foo 是 integer (1)
$foo = 1 + "10 Small Pigs";       // PHP 8.0.0 起，$foo 是 integer (11)，并且产生 E_WARNING；在此之前产生 E_NOTICE
$foo = 4 + "10.2 Little Piggies"; // PHP 8.0.0 起，$foo 是 float (14.2)，并且产生 E_WARNING；在此之前产生 E_NOTICE
$foo = "10.0 pigs " + 1;          // PHP 8.0.0 起，$foo 是 float (11)，并且产生 E_WARNING；在此之前产生 E_NOTICE
$foo = "10.0 pigs " + 1.0;        // PHP 8.0.0 起，$foo 是 float (11)，并且产生 E_WARNING；在此之前产生 E_NOTICE
?>
```



### array 数组

PHP 中的 **array** 实际上是一个有序映射。映射是一种把 **values** 关联到 **keys** 的类型。

它可以被视为数组、列表（向量）、哈希表（映射的实现）、字典、集合、堆栈、队列等等。



#### 定义数组 array()

可以用 **array()** 语言结构来新建一个 **array**。它接受任意数量用逗号分隔的 键 `（key） => 值（value）` 对。

*key* 可以是 **integer** 或者 **string**。*value* 可以是任意类型。

```php
array(
    key  => value,
    key2 => value2,
    key3 => value3,
    ...
)
```

最后一个数组单元之后的逗号可以省略。。通常用于单行数组定义中，例如常用 `array(1, 2)` 而不是 `array(1, 2, )`。对多行数组定义通常保留最后一个逗号，这样要添加一个新单元时更方便。

**注意**：可以用短数组语法 `[]` 替代 `array()` 。



**示例 #1 一个简单数组**

```php
<?php
$array = array(
    "foo" => "bar",
    "bar" => "foo",
);

// 使用短数组语法
$array = [
    "foo" => "bar",
    "bar" => "foo",
];
?>
```

此外 key 会有如下的强制转换：

- **String** 中包含有效的十进制 **int**，除非数字前面有一个 + 号，否则将被转换为 **int** 类型。例如键名 "8" 实际会被储存为 8。另外， "08" 不会被强制转换，因为它不是一个有效的十进制整数。
- **Float** 也会被转换为 **int** ，意味着其小数部分会被舍去。例如键名 8.7 实际会被储存为 8。
- **Bool** 也会被转换成 **int**。即键名 **true** 实际会被储存为 1 而键名 **false** 会被储存为 0。
- **Null** 会被转换为空字符串，即键名 null 实际会被储存为 ""。
- **Array** 和 **object** 不能 被用为键名。坚持这么做会导致警告：Illegal offset type。

如果在数组定义时多个元素都使用相同键名，那么只有最后一个会被使用，其它的元素都会被覆盖。



**示例 #2 没有键名的索引数组**

*key* 为可选项。如果未指定，PHP 将自动使用之前用过的最大 **int** 键名加上 1 作为新的键名。

```php
<?php
$array = array("foo", "bar", "hello", "world");
var_dump($array);
?>
```

以上示例会输出：

```php
array(4) {
  [0]=>
  string(3) "foo"
  [1]=>
  string(3) "bar"
  [2]=>
  string(5) "hello"
  [3]=>
  string(5) "world"
}
```



**示例 #3 仅对部分单元指定键名**

可以看到最后一个值 `"d"` 被自动赋予了键名 `7`。这是由于之前最大的整数键名是 `6`。

```php
<?php
$array = array(
         "a",
         "b",
    6 => "c",
         "d",
);
var_dump($array);
?>
```

以上示例会输出：

```
array(4) {
  [0]=>
  string(1) "a"
  [1]=>
  string(1) "b"
  [6]=>
  string(1) "c"
  [7]=>
  string(1) "d"
}
```



**示例 #4 类型转换与覆盖的示例**

```php
<?php
$array = array(
    1    => "a",
    "1"  => "b",
    1.5  => "c",
    true => "d",
);
var_dump($array);
?>
```

以上示例会输出：

```php
array(1) {
  [1]=>
  string(1) "d"
}
```





#### 用方括号语法访问数组单元

数组单元可以通过 `array[key]` 语法来访问。

**注意**：在 PHP 8.0.0 之前，方括号和花括号可以互换使用来访问数组单元（例如 `$array[42]` 和 `$array{42}` 在上例中效果相同）。 花括号语法在 PHP 7.4.0 中已弃用，在 PHP 8.0.0 中不再支持。

**示例 #7 访问数组单元**

```php
<?php
$array = array(
    "foo" => "bar",
    42    => 24,
    "multi" => array(
         "dimensional" => array(
             "array" => "foo"
         )
    )
);

var_dump($array["foo"]);
var_dump($array[42]);
var_dump($array["multi"]["dimensional"]["array"]);
?>
```

以上示例会输出：

```
string(3) "bar"
int(24)
string(3) "foo"
```





**示例 #8 数组解引用**

**注意**：试图访问一个未定义的数组键名与访问任何未定义变量一样：会导致 **`E_WARNING`** 级别错误信息（在 PHP 8.0.0 之前是 **`E_NOTICE`** 级别），其结果为 **`null`**。

```php
<?php
function getArray() {
    return array(1, 2, 3);
}

$secondElement = getArray()[1];
?>
```



数组解引用非 **string** 的标量值会产生 `null`。

在 PHP 7.4.0 之前，它不会发出错误消息。 从 PHP 7.4.0 开始，这个问题产生 **E_NOTICE** ； 从 PHP 8.0.0 开始，这个问题产生 **E_WARNING** 。

```php
$scalar = 42; // 这是一个整数标量值
echo $scalar[0]; // 这行会触发一个警告，因为 $scalar 不是一个数组
```



#### 用方括号的语法新建／修改

在方括号内指定键名来给 **array** 进行赋值。也可以省略键名，在这种情况下给变量名加上一对空的方括号（[]）。

```php
$arr[key] = value;
$arr[] = value;
// key 可以是 int 或 string
// value 可以是任意类型的值
```

如果 $arr 不存在或者设置为 **`null`** 或者 **`false`**，将会新建它，这也是另一种创建 array 的方法。

> **注意**：从 PHP 7.1.0 起，对字符串应用空索引操作符会抛出致命错误。以前，字符串被静默地转换为数组。

> **注意**：从 PHP 8.1.0 起，弃用从 **false** 值中创建一个新数组。 但仍然允许从 **null** 或者未定义的变量中创建新数组。



要修改某个值，通过其键名给该单元赋一个新值。要删除某键值对，对其调用 **unset()** 函数。

```php
<?php
$arr = array(5 => 1, 12 => 2);

$arr[] = 56;    // 这与 $arr[13] = 56 相同;
                // 在脚本的这一点上

$arr["x"] = 42; // 添加一个新元素
                // 键名使用 "x"
                
unset($arr[5]); // 从数组中删除元素

unset($arr);    // 删除整个数组
?>
```



如果 *key* 未指定，PHP 将自动使用之前用过的最大 **int** 键名加上 1 作为新的键名，当前还没有 **int** 索引，则键名将为 0 。

unset() 函数允许删除 array 中的某个键。但要注意数组将不会重建索引。如果需要删除后重建索引，可以用 array_values() 函数重建 array 索引。

以下面的例子来说明：

```php
<?php
// 创建一个简单的数组
$array = array(1, 2, 3, 4, 5);
print_r($array);

// 现在删除其中的所有元素，但保持数组本身不变:
foreach ($array as $i => $value) {
    unset($array[$i]);
}
print_r($array);

// 添加一个单元（注意新的键名是 5，而不是你可能以为的 0）
$array[] = 6;
print_r($array);

// 重新索引：
$array = array_values($array);
$array[] = 7;
print_r($array);
?>
```

以上示例会输出：

```
Array
(
    [0] => 1
    [1] => 2
    [2] => 3
    [3] => 4
    [4] => 5
)
Array
(
)
Array
(
    [5] => 6
)
Array
(
    [0] => 6
    [1] => 7
)
```



#### 数组解包

可以使用 []（自 PHP 7.1.0 起）或者 **list()** 语言结构解包数组。这些结构可用于将数组解包为不同的变量。

```php
<?php
$source_array = ['foo', 'bar', 'baz'];

[$foo, $bar, $baz] = $source_array;

echo $foo;    // 打印 "foo"
echo $bar;    // 打印 "bar"
echo $baz;    // 打印 "baz"
?>
```



数组解包可用于 foreach 在迭代多维数组时对其进行解包。

```php
<?php
$source_array = [
    [1, 'John'],
    [2, 'Jane'],
];

foreach ($source_array as [$id, $name]) {
    // 这里是 $id 和 $name 的逻辑
}
?>
```



如果变量未提供，数组元素将会被忽略。数组解包始终从索引 `0` 开始。

```php
<?php
$source_array = ['foo', 'bar', 'baz'];

// 将索引 2 的元素分配给变量 $baz
[, , $baz] = $source_array;

echo $baz;    // 打印 "baz"
?>
```



自 PHP 7.1.0 起，也可以解包关联数组。这在数字索引数组中更容易选择正确的元素，因为可以显式指定索引。

```php
<?php
$source_array = ['foo' => 1, 'bar' => 2, 'baz' => 3];

// 将索引 'baz' 处的元素分配给变量 $three
['baz' => $three] = $source_array;

echo $three;    // 打印 3

$source_array = ['foo', 'bar', 'baz'];

// 将索引 2 处的元素分配给变量 $baz
[2 => $baz] = $source_array;

echo $baz;    // 打印 "baz"
?>
```



数组解包可以方便的用于两个变量交换。

```php
<?php
$a = 1;
$b = 2;

[$b, $a] = [$a, $b];

echo $a;    // 打印 2
echo $b;    // 打印 1
?>
```

