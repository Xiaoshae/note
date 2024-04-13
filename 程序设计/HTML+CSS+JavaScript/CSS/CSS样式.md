# CSS盒子模型

CSS盒模型本质上是一个盒子，封装周围的HTML元素，它包括：边距，边框，填充，和实际内容。

![CSS box-model](images/CSS样式.assets/box-model.gif)

- **Margin(外边距)** - 清除边框外的区域，外边距是透明的。
- **Border(边框)** - 围绕在内边距和内容外的边框。
- **Padding(内边距)** - 清除内容周围的区域，内边距是透明的。
- **Content(内容)** - 盒子的内容，显示文本和图像。



当您指定一个 CSS 元素的宽度和高度属性时，你只是设置内容区域的宽度和高度。

完整大小的元素，你还必须添加内边距，边框和外边距。



总元素的宽度=宽度+左填充+右填充+左边框+右边框+左边距+右边距

总元素的高度=高度+顶部填充+底部填充+上边框+下边框+上边距+下边距



# 盒子样式



## margin

**`margin`** 属性为给定元素设置所有四个（上右下左）方向的外边距属性。

`margin-top`、`margin-right`、`margin-bottom` 和 `margin-left` 四个外边距属性设置的简写。



**`margin`** 属性接受 1~4 个值。每个值可以是 `<length>`，`<percentage>`，或 `auto`。

取值为负时元素会比原来更接近临近元素。

- 当只指定**一个**值时，该值会统一应用到**全部四个边**的外边距上。
- 指定**两个**值时，第一个值会应用于**上边和下边**的外边距，第二个值应用于**左边和右边**。
- 指定**三个**值时，第一个值应用于**上边**，第二个值应用于**右边和左边**，第三个则应用于**下边**的外边距。
- 指定**四个**值时，依次（顺时针方向）作为**上边**，**右边**，**下边**，和**左边**的外边距。



**可取值**：

**`<length>`**
以固定值为外边距。

**`<percentage>`**
相对于包含块的宽度，以百分比值为外边距。

**`auto`**
让浏览器自己选择一个合适的外边距。有时，在一些特殊情况下，该值可以使元素居中。



## Padding

padding 属性控制元素所有四条边的内边距区域。

该属性是以下属性的简写：`padding-bottom`、`padding-left`、`padding-right`、`padding-top`



`padding` 属性接受 1~4 个值（值数量含义与margin含义相同）。

每个值可以是 `<length>`  或 `<percentage>`（与margin可取值含义相同）。取值不能为负。



## border

**`border`** 用于设置各种单独的边界属性。

用于设置一个或多个以下属性的值：`border-width`、`border-style`、`border-color`。



border 属性只接受三个参数，分别是宽度、风格和颜色，所以这样会使得**四条边的边框相同**。

由于border属性接收的三个参数的值类型是不同得，所以没有顺序要求。

```
border: [border-width] [border-style] [border-color]
border: [border-color] [border-width] [border-style]
border: [border-style] [border-color] [border-width]
```



## border-color

border-color 是一个用于设置元素四个边框颜色的快捷属性： `border-top-color`、`border-right-color`、`border-bottom-color`、`border-left-color`。



border-color支持1~4个值：

- 当只指定**一个**值时，该值会统一应用到**全部四个边**的边框颜色上。
- 指定**两个**值时，第一个值会应用于**上边和下边**的边框颜色，第二个值应用于**左边和右边**。
- 指定**三个**值时，第一个值应用于**上边**，第二个值应用于**右边和左边**，第三个则应用于**下边**的边框颜色。
- 指定**四个**值时，依次（顺时针方向）作为**上边**，**右边**，**下边**，和**左边**的边框颜色。



inherit：用于指示四边的颜色值均继承自父元素的计算：

```css
div {
    border-color: inherit;
}
```