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





