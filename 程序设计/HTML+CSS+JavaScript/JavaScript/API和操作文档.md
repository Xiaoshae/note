# 什么是 API?

应用程序接口（API，Application Programming Interface）是基于编程语言构建的结构，使开发人员更容易地创建复杂的功能。它们抽象了复杂的代码，并提供一些简单的接口规则直接使用。



## 客户端 JavaScript 中的 API

客户端 JavaScript 中有很多可用的 API — 他们本身并不是 JavaScript 语言的一部分，却建立在 JavaScript 语言核心的顶部，为使用 JavaScript 代码提供额外的超强能力。他们通常分为两类：

**浏览器 API**内置于 Web 浏览器中，能从浏览器和电脑周边环境中提取数据，并用来做有用的复杂的事情。例如：**DOM（文档对象模型API）。**

**第三方 API**缺省情况下不会内置于浏览器中，通常必须在 Web 中的某个地方获取代码和信息。例如 **YouTube API** , 允许你将 Youtube 上的视频嵌入到网站中去，同时提供搜索 Youtube，创建播放列表等众多功能。

## API 可以做什么？

**操作文档的 API**内置于浏览器中。最明显的例子是**DOM（文档对象模型）API**，它允许你操作 HTML 和 CSS — 创建、移除以及修改 HTML，动态地将新样式应用到你的页面，等等。每当你看到一个弹出窗口出现在一个页面上，或者显示一些新的内容时，这都是 DOM 的行为。



## API 如何工作？

它们是基于对象的。API 使用一个或多个 JavaScript objects 在你的代码中进行交互，这些对象用作 API 使用的数据（包含在对象属性中）的容器以及 API 提供的功能（包含在对象方法中）。



下面将详细介绍**DOM（文档对象模型）API**的使用。



# DOM API

文档对象模型（DOM）用于控制 HTML 和样式信息的 API，大量使用了 Document 对象。



## 浏览器的重要部分

考虑下图，它代表了浏览器中直接参与浏览网页的主要部分：

![web 浏览器的重要部分；文档就是网页。窗口包括整个文档，也包括标签。导航器是浏览器，它包括窗口（包括文档）和所有其他窗口](./images/API%E5%92%8C%E6%93%8D%E4%BD%9C%E6%96%87%E6%A1%A3.assets/document-window-navigator.png)

窗口（window）是载入网页的浏览器标签；在 JavaScript 中，它由 Window 对象表示。例如：返回窗口的大小（见 **Window.innerWidth** 和 **Window.innerHeight**）。操作加载到窗口的文档，为当前窗口附加一个**事件处理器**等。

导航器（navigator）在网络上出现时，代表浏览器的状态和身份（即用户代理）。在 JavaScript 中，它由 Navigator 对象表示。例如：检索用户的首选语言、用户网络摄像头的媒体流等信息。

文档（document，在浏览器中用 DOM 表示）是加载到窗口的实际页面，在 JavaScript 中，它由 Document 对象表示。例如：返回和操作构成文档的 HTML 和 CSS 的信息。



## 文本对象模型

目前在你的每一个浏览器标签中加载的文档是由一个文档对象模型表示的。这是一个由浏览器创建的“树状结构”表示法，使 HTML 结构能够被编程语言轻松访问。例如，浏览器本身在渲染页面时使用它将样式和其他信息应用于正确的元素，而开发者可以在页面渲染后用 JavaScript 来操作 DOM。

HTML 源代码看起来像这样：

```html
<!doctype html>
<html lang="en-US">
  <head>
    <meta charset="utf-8" />
    <title>Simple DOM example</title>
  </head>
  <body>
    <section>
      <img
        src="dinosaur.png"
        alt="A red Tyrannosaurus Rex: A two legged dinosaur standing upright like a human, with small arms, and a large head with lots of sharp teeth." />
      <p>
        Here we will add a link to the
        <a href="https://www.mozilla.org/">Mozilla homepage</a>
      </p>
    </section>
  </body>
</html>
```

其 DOM 树如下所示：

![文档对象模型的树状结构表示：顶部节点是 doctype 和 HTML 元素。HTML 的子节点包括 head 和 body。每个子元素都是一个分支。所有的文本，甚至是空白处，也都被显示出来](./images/API%E5%92%8C%E6%93%8D%E4%BD%9C%E6%96%87%E6%A1%A3.assets/dom-screenshot.png)

树上的每个条目都被称为**节点**。你可以在上图中看到，一些节点代表元素（标识为 `HTML`、`HEAD`、`META` 等），另一些代表文本（标识为 `#text`）。

节点也通过它们在树中相对于其他节点的位置来指代：

- **根节点**: 树中顶层节点，在 HTML 的情况下，总是一个 `HTML` 节点（其他标记词汇，如 SVG 和定制 XML 将有不同的根元素）。
- **子节点**: *直接*位于另一个节点内的节点。例如上面例子中，`IMG` 是 `SECTION` 的子节点。
- **后代节点**: 位于另一个节点内*任意位置*的节点。例如 上面例子中，`IMG` 是 `SECTION` 的子节点，也是一个后代节点。`IMG` 不是 `BODY` 的子节点，因为它在树中比 `BODY` 低了两级，但它是 `BODY` 的后代之一。
- **父节点**: 里面有另一个节点的节点。例如上面的例子中 `BODY` 是 `SECTION` 的父节点。
- **兄弟节点**: DOM 树中位于同一等级的节点。例如上面例子中，`IMG` 和 `P` 是兄弟。



## 基本的 DOM 操作

要操作 DOM 内的元素，首先需要选择它，并将它的引用存储在一个变量中。在 script 元素中，添加下列代码行：

```javascript
const link = document.querySelector("a");
```



现在我们已经将元素引用存储在一个变量中，我们可以开始使用可用的属性和方法来操作它（它们定义在 `<a>` 元素的 HTMLAnchorElement 接口上，它继承于更一般的父接口 HTMLElement，以及 Node——它代表 DOM 中所有节点）。

更新 Node.textContent 属性的值来改变链接中的文本。在前一行下面添加以下内容：

```javascript
link.textContent = "Mozilla Developer Network";
```



我们也能修改链接指向的 URL，使得它被点击时不会走向错误的位置。在底部再次加入下列代码：

```javascript
link.href = "https://developer.mozilla.org";
```



有许多方法可以**选择一个元素**并将其引用存储在一个变量中，Document.querySelector() 是推荐的方法。上面的 querySelector() 调用将匹配文档中出现的第一个 `<a>` 元素

Document.querySelectorAll()，**多个元素**进行匹配和操作，匹配文档中与选择器相匹配的每个元素，并将它们的引用存储在一个叫做 NodeList 的数组对象中。

对于获取元素引用，还有一些更旧的方法，如：

- Document.getElementById()，选择一个 `id` 属性值已知的元素，例如 `<p id="myId">My paragraph</p>`。ID 作为参数传递给函数，即 `const elementRef = document.getElementById('myId')`。
- Document.getElementsByTagName()，返回页面中包含的所有已知类型元素的数组。如 `<p>`、`<a>` 等。元素类型作为参数传递给函数，即 `const elementRefArray = document.getElementsByTagName('p')`。



## 创建并放置新的节点

获取到 `<section>` 元素的引用：

```javascript
const sect = document.querySelector("section");
```

Document.createElement() 创建一个新的段落，用与之前相同的方法赋予相同的文本：

```javascript
const para = document.createElement("p");
para.textContent = "We hope you enjoyed the ride.";
```

Node.appendChild() 方法在后面追加新的段落：

```javascript
sect.appendChild(para);
```



在内部链接的段落中添加文本节点，完美的结束句子。

Document.createTextNode() 创建一个文本节点：

```javascript
const text = document.createTextNode(
  " — the premier source for web development knowledge.",
);
```

获取内部连接的段落的引用，并把文本节点附加到这个节点上：

```javascript
const linkPara = document.querySelector("p");
linkPara.appendChild(text);
```



## 移动和删除元素

把具有内部链接的段落移到 section 的底部，简单的做法是：

```javascript
sect.appendChild(linkPara);
```

这样可以把段落下移到 section 的底部。它不会产生第二个副本，而是直接的移动。linkPara 是对该段落唯一副本的引用。如果你想复制并添加它，你需要使用 Node.cloneNode() 来代替。



Node.removeChild()删除节点：

```javascript
sect.removeChild(linkPara);
```



Element.remove() 删除一个仅基于自身引用的节点：

```javascript
linkPara.remove();
```



此方法在较旧的浏览器中没有方法告诉一个节点删除自己，需要使用以下方法：

```javascript
linkPara.parentNode.removeChild(linkPara);
```



## 操作样式

HTMLElement.style 属性包含了文档中每个元素的内联样式信息，设置这个对象的属性来直接更新元素样式：

```javascript
para.style.color = "white";
para.style.backgroundColor = "black";
para.style.padding = "10px";
para.style.width = "250px";
para.style.textAlign = "center";
```

重新载入页面，你将看到样式已经应用到段落中：

```html
<p
  style="color: white; background-color: black; padding: 10px; width: 250px; text-align: center;">
  We hope you enjoyed the ride.
</p>
```

**备注：** 请注意，CSS 样式的 JavaScript 属性版本是用小驼峰命名法书写的，而 CSS 版本是连字符的（例如，`backgroundColor` 对 `background-color`）。确保你不要把这些混为一谈，否则将无法工作。



Element.setAttribute() 接受两个参数：想在元素上设置的属性、要为它设置的值。

在 HTML 的 `<head>` 中添加下列代码 :

```css
<style>
  .highlight {
    color: white;
    background-color: black;
    padding: 10px;
    width: 250px;
    text-align: center;
  }
</style>
```

在段落中设置类名为 highlight：

```javascript
para.setAttribute("class", "highlight");
```

通过给它一个类，由 CSS 规则选择，而不是作为内联 CSS 样式。



