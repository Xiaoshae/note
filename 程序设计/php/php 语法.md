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

