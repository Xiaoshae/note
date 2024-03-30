# 引入CSS样式

## 1. 行内式

**行内式**：也称为内联样式，是直接在 HTML 元素中使用 `style` 属性来定义 CSS 规则。

```html
<div style="color: red;">这是红色文本</div>
```



## 2. 内嵌式

**内嵌式**：是在 HTML 文档的 `<head>` 部分使用 `<style>` 标签来定义 CSS 规则。例如：

```html
<style>
div {
    color: red;
}
</style>
```



## 3. 外联式

**外链式**：是通过 `<link>` 标签引入外部 CSS 文件。

```html
<link rel="stylesheet" href="styles.css">
```



## 4.导入式

**导入式**：是在 CSS 文件或 `<style>` 标签中使用 `@import` 规则来引入外部 CSS 文件。

```html
@import url('styles.css');
```





# CSS选择器

## 1. 通配符选择器

通配符选择器（`*`）可以匹配页面中的所有元素。

```css
* {
	color: red;
}
```

把页面中所有元素的文本颜色设置为红色。



## 2. 标签选择器

标签选择器可以匹配页面中所有特定类型的元素。

```css
p {
	text-align: center;
}
```

将把页面中所有 `<p>` 元素的文本对齐方式设置为居中。



## 3. 类选择器

类选择器可以匹配页面中所有具有特定类的元素。

```css
.highlight {
	background-color: yellow;
}
```

把页面中所有类为 `highlight` 的元素的背景颜色设置为黄色。



使用 `class` 属性来指定元素的类：

```html
<div class="highlight">这是一个黄色背景的 div 元素。</div>
```



## 4. ID选择器

ID选择器可以匹配页面中具有特定 ID 的元素。

```css
#myId {
	font-size: 20px;
}
```

把页面中 ID 为 `myId` 的元素的字体大小设置为 20 像素。



你可以使用 `id` 属性来指定元素的 ID：

```html
<div id="myId">这是一个字体大小为 20 像素的 div 元素。</div>
```



## 5. class 和 id

同时设置多个类，只需要在 `class` 属性中用空格分隔每个类名即可。例如：

```html
<div class="class1 class2 class3">这是一个 div 元素，它有三个类：class1、class2 和 class3。</div>
```

---

每个元素只能有一个唯一的 ID，不能设置多个ID，例如：

```html
<div id="myId">这是一个 div 元素，它的 ID 是 myId。</div>
```

---

同时设置类（class）和 ID。例如：

```html
<div class="myClass" id="myId">这是一个 div 元素，它的类是 myClass，ID 是 myId。</div>
```

```html
<div class="myClass1 myClass2 myClass3" id="myId">这是一个 div 元素，它的类是 myClass1 myClass2 myClass3，ID 是 myId。</div>
```



# 复合选择器

## 1. 后代

后代选择器可以匹配某个元素内部的所有后代元素。

例如，`div p` 将选择所有 `div` 元素内部的 `p` 元素，无论 `p` 元素在 `div` 元素内部的深度如何。

CSS：

```css
div p {
	color:red;
}
```



HTML：

```HTML
<div>
    <p>这是一个红色的段落。</p>
    <div>
        <p>这也是一个红色的段落，尽管它在一个 div 内部。</p>
    </div>
</div>
```



---



CSS：

```css
div div p {
	color:red;
}
```



HTML：

```HTML
<div>
    <p> 这个段落没有颜色。</p>
    <div>
        <p> 这是一个红色的段落。 </p>
    </div>
</div>
```





## 2. 交集

标签指定选择器可以匹配**同时满足多个条件**的元素。

```css
h3.special{
	color:red;
}
```

选择的元素要求同时满足两个条件：必须是h3标签，然后必须是special类选择器。

![CSS的四种基本选择器和四种高级选择器[通俗易懂]](images/CSS基础.assets/3e1e33aa510b8f591eb47573caa90164.png)



```HTML
<h3 class="special">我是红色</h3>
<p class="special">没有颜色</p>
```

1. 同时满足h3标签和special类选择器
2. 只满足special类选择器



## 3. 并集

并集选择器可以匹配多个选择器所选择的所有元素。

例如，`h1, h2, h3` 将选择所有 `h1`、`h2` 和 `h3` 元素。

CSS：

```css
h1, h2, h3 {
    color: blue;
}
```



HTML：

```css
<h1>这是一个蓝色的标题。</h1>
<h2>这也是一个蓝色的标题。</h2>
<h3>这还是一个蓝色的标题。</h3>
<p>这是一个没有颜色的段落。</p>
```



# 优先级和权重

## 1. 优先级

优先级决定了当多个 CSS 规则应用到同一个元素时，哪一个规则会被优先应用。

1. **!important**：`!important` 规则总是最优先的。

2. **内联样式**：在 HTML 元素中直接使用的 `style` 属性。

3. **ID 选择器**：如 `#myId`。

4. **类选择器**、**属性选择器**和**伪类选择器**：如 `.myClass`，`[type="text"]`，`:hover`。

5. **标签选择器**和**伪元素选择器**：如 `div`，`::before`。

6. **源顺序**：如果权重相同，那么在 CSS 文件中后出现的规则将优先应用。

    注：这是因为 CSS 是一种 “层叠” 的样式表语言，后定义的规则会覆盖先定义的规则。

---

### 1.1 `!important` vs 内联样式

CSS：

```css
#myId {
    color: red !important;
}
```



HTML：

```html
<p id="myId" style="color: blue;"> 颜色为红色。</p>
```

`!important` 规则的优先级高于**内联样式**

---

### 1.2 联样式 vs 类选择器

CSS：

```css
.myClass {
    color: red;
}
```



HTML：

```html
<div class="myClass" style="color: blue;"> 蓝色。</div>
```

---

### 1.3 ID 选择器 vs 类选择器

CSS：

```css
#myId {
    color: blue;
}

.myClass {
    color: red;
}
```



HTML：

```html
<div id="myId" class="myClass"> 蓝色。</div>
```

---

### 1.4 类选择器 vs 标签选择器

CSS：

```css
p {
    color: blue;
}

.myClass {
    color: red;
}
```



HTML：

```html
<p class="myClass"> 蓝色。</div>
<p> 红色。</div>
```

---

### 1.5 源顺序

CSS：

```css
.myClass1 {
    color: blue;
}

.myClass2 {
    color: red;
}
```



HTML：

```html
<p class="myClass1 myClass2"> 红色 </p>
<p class="myClass2 myClass3"> 红色 </p>
```

注：与class中设置的顺序无关。

---

CSS：

```css
.myClass1 {
	color:red !important;
}

.myClass2 {
	color:blue !important;
}
```



HTML：

```html
<div  class="myClass1 myClass2">
	<p> 红色？。 </p>
</div>
```





## 2. 权重

每种类型的选择器都有一个权重值，这个值用于在多个规则冲突时确定哪个规则应该被应用。

后代复合选择器，权重可以被累加。

权重相同时按照源顺序。



**`!important` 规则**优先级最高，**内联样式**优先级其次，这两个规则不受权重影响，即使其他类型权重累加高于它们。****

---

**权重值**：

1. **ID 选择器**：100
2. **类选择器**、**属性选择器**和**伪类选择器**：10
3. **标签选择器**和**伪元素选择器**：1

---



CSS：

```css
#myID p {			<!-- ID(100) + 标签(1) = 101 -->
	color:red;
}

.myClass p {		<!-- 类(10) + 标签(1) = 11 -->
	color:blue;
}
```



HTML：

```HTML
<div id="myID" class="myClass">
	<p> 红色。 </p>
</div>
```



# 层叠和继承

## 1. 层叠

“层叠” 是 CSS 中的一个重要概念，如果有多个 CSS 规则应用到同一个元素时，会按照优先级和权重决定那一条规则被优先应用。



## 2. 继承

“继承” 是 CSS 中的另一个重要概念。在 CSS 中，一些样式属性是可以从父元素继承到子元素的。

这意味着，如果你为一个元素设置了某个属性，那么这个元素的所有子元素都会自动获取这个属性，除非你为子元素显式设置了这个属性。

---

```HTML
<div style="color: red;">
    这是红色文本。
    <p>这也是红色文本，因为它继承了父元素 div 的颜色。</p>
</div>
```

---

```HTML
<div style="color: red;">
    这是红色文本。
    <p style="color: blue"> 这是蓝色文本。 </p>
</div>
```



## 3. 样式取消

通过内联样式或 `!important` 规则来取消设置的样式。

---

例1：在class中设置了样式，该标签应用了class，其他属性应用，但不应用颜色属性。则可以通过 内联样式优先级高于class 来通过层叠特性取消颜色属性。

CSS：

```css
.myClass {
    color:red;
    font-size:20px;
}
```



HTML：

```HTML
<p class="myClass" style="color: initial;"> 默认颜色。 </p>
```

---

例2：为子元素显式设置了这个属性，取消继承。

```css
<div style="color: red;">
    这是红色文本。
    <p style="color: blue"> 这是蓝色文本。 </p>
</div>
```

