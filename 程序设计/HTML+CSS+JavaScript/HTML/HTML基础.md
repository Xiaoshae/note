# HTML 基础

HTML（HyperText Markup Language，超文本标记语言）是一种用来**告知浏览器如何组织页面**的标记语言。



文档结构

```html
<!doctype html>
<html lang="zh-CN">
    
    <head>
        <meta charset="utf-8" />
        <title>
            我的测试站点
        </title>
    </head>
    
    <body>
        <p>
            这是我的页面
        </p>
    </body>

</html>
```

## 1. 文档类型

`<!DOCTYPE html>`：声明文档类型。

文档类型是一个历史遗留问题，需要包含它才能使其他东西正常工作。

现在，只需要知道 `<!DOCTYPE html>` 是最短的有效文档声明！



## 2. html元素

`<html></html>`：`<html>` 元素。

这个元素包裹了页面中所有的内容，有时被称为根元素。

里面也包含了 lang 属性，写明了页面的主要语种。



## 3. head元素

`<head></head>`: `<head>`元素。

这个元素是一个容器，它包含了所有你想包含加到页面中，且**不向用户展示**的内容。

这些内容包括**关键字、页面描述、CSS 样式、字符集声明**等等。



## 4. body元素

1. `<body></body>`：`<body>`元素。

包含了你访问页面时**所有**显示在页面上的内容，包含文本、图片、视频、游戏、可播放音频轨道等等。





# 元素



![HTML 元素](images/HTML基础.assets/grumpy-cat-small.png)

**元素**（Element）：开始标签、结束标签与内容相结合，便是一个完整的元素。

1. **开始标签**（Opening tag）：用**大于号、小于号包围包元素的名称**（本例为 p），**表示元素的开始**。
2. **结束标签**（Closing tag）：与开始标签相似，在元素名前包含一个斜杠，表示着**元素的结尾**。
3. **内容**（Content）：元素的内容，本例中就是所输入的文本本身。





## 嵌套元素

将一个元素置于其他元素之中——称作**嵌套**。

要表明猫咪非常暴躁，可以将“very”用`<strong>`元素包围，“very”将突出显示：

```html
<p>My cat is <strong>very</strong> grumpy.</p>
```



**元素嵌套次序**：

本例首先使用 `<p>` 标签，然后是 `<strong>` 标签，因此要先结束 `<strong>` 标签，最后再结束 `<p>` 标签。



## 空元素

不包含任何内容的元素称为空元素。比如 `<img>` 元素：

```html
<img src="images/firefox-icon.png" alt="My test image" />
```

本元素包含两个属性，但是并没有 `<img>` 结束标签，但是需要在右`>`前面加上`/`，元素里也没有内容。



## 块级和内联元素

在 HTML 中有块级元素和内联元素：

- **块级元素**：在页面中以块的形式展现。一个块级元素出现在它前面的内容之后的新行上。
- **内联元素**：通常出现在块级元素中并环绕文档内容的一小部分，而不是一整个段落或者一组内容。内联元素不会导致文本换行。





# 属性

![HTML 属性](images/HTML基础.assets/grumpy-cat-attribute-small.png)

属性包含了关于元素的一些额外信息，这些信息本身不应显现在内容中。

例中，`class` 是**属性名称**，`editor-note` 是**属性的值**。

**`class` 属性可为元素提供一个标识名称，以便进一步为元素指定样式或进行其他操作时使用。**



属性应该包含：

1. 在属性与元素名称（或上一个属性，如果有超过一个属性的话）之间的空格符。
2. 属性的名称，并接上一个等号。
3. 由引号所包围的属性值。



## 布尔属性

**没有值的属性**被称为布尔属性。布尔属性只能有一个值，这个值一般与属性名称相同。



例如，考虑 `disabled` 属性，你可以将其分配给表单输入元素。用它来禁用表单输入元素，这样用户就不能输入了。被禁用的元素通常有一个灰色的外观。示例如下：

```html
<input type="text" disabled="disabled" />
```



可以将其写成以下形式：

```html
<!-- 使用 disabled 属性来防止终端用户输入文本到输入框中 -->
<input type="text" disabled />

<!-- 下面这个输入框不包含 disabled 属性，所以用户可以向其中输入 -->
<input type="text" />
```



## 省略包围属性值的引号

不包含 ASCII 空格（以及 `"` `'` ``` `=` `<` `>`）的简单属性值可以不使用引号，但是建议将所有属性值用引号括起来，这样的代码一致性更佳，更易于阅读。



拥有一个 `href` 属性的版本：

```html
<a href=https://www.mozilla.org/>favorite website</a>
```



添加一个这样的 `title` 属性时，就会出现问题：

它会理解为三个属性——title 的属性值为 `The`，另外还有两个布尔属性 `Mozilla` 和 `homepage`



## 单引号或双引号

用单引号或双引号用来包裹属性的值都是可以的：

```html
<a href='https://www.example.com'>示例站点链接</a>

<a href="https://www.example.com">示例站点链接</a>
```



一个 HTML 中已使用一种引号，你可以在此引号中嵌套另外一种引号：

```html
<a href="https://www.example.com" title="你觉得'好玩吗'？">示例站点链接</a>
```



如果你想将英文引号（单引号或双引号）当作文本显示在 html 中，你就必须使用 **HTML 实体引用**。

```html
<a href="https://www.example.com" title="Isn&apos;t this fun?">示例站点链接</a>
```





# 实体引用

在 HTML 中，字符 `<`、`>`、`"`、`'` 和 `&` 是特殊字符。

我们必须使用字符引用——表示字符的特殊编码，它们可以在那些情况下使用。每个字符引用以符号 & 开始，以分号（;）结束。



| 原义字符 | 等价字符引用 |
| :------- | :----------- |
| <        | `&lt;`       |
| >        | `&gt;`       |
| "        | `&qout;`     |
| '        | `&qpos;`     |
| &        | `&amp;`      |



# 简单标签

## 图片

重温一下 `<img>`元素：

```html
<img src="images/firefox-icon.png" alt="My test image" />
```

该元素通过包含图像文件路径的地址属性 `src`，可在所在位置嵌入图像。



该元素还包括一个替换文字属性 `alt`，是图像的描述内容，用于当图像不能被用户看见时显示。

1. 用户有视觉障碍。视障用户可以使用屏幕阅读器来朗读 `alt` 属性的内容。
2. 有些错误使图像无法显示。可以试着故意将 `src` 属性里的路径改错。保存并刷新页面就可以在图像位置看到：

![图片内容为文字“测试图片”](images/HTML基础.assets/alt-text-example.png)



alt 属性的关键字即“描述文本”，alt 文本应向用户完整地传递图像要表达的意思。

这里原本所展示的图片为 Firefox图标，用 "My test image" 来描述 Firefox 标志并不合适，修改成 "Firefox 标志：一只盘旋在地球上的火狐" 。





## 链接

```html
<a href="https://www.mozilla.org/zh-CN/about/manifesto/">Mozilla Manifesto</a>
```

1. `<a>`是文本标签，展示的文本包含在其中。
2. `href` 属性，用于指定一个跳转的链接。



**备注**： href全称为**h**ypertext **ref**erence

