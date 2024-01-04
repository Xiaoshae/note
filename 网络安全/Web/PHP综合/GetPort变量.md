# php get or post 变量名特性

在php中变量名只有数字字母下划线，被get或者post传入的变量名，如果含有`空格、+、[`则会被转化为`_`,但php中有个特性就是如果传入`[`，它被转化为`_`之后，后面的字符就会被保留下来不会被替换。



## 示例

```
abc+abc.123
abc_abc_123

abc[abc.123
abc_abc.123

abc_abc+abc abc.123
abc_abc_abc_abc_123

abc[abc+abc abc.123
abc_abc+abc abc.123
```

