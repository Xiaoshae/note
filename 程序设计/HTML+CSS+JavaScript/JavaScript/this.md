# this

在JavaScript中，`this`关键字是一个核心概念，它通常用于引用当前执行上下文的对象。`this`的值在函数调用时动态确定，而不是在编写代码时静态确定的，这种特性被称为动态作用域或运行时绑定。`this`的值依赖于函数的调用方式，下面是一些主要的场景：



## 全局作用域中的 `this`

在全局作用域中，`this`通常指向全局对象：

- 在浏览器环境中，全局对象是`window`。
- 在Node.js环境中，全局对象是`global`。



## 普通函数调用

当一个函数被简单地调用，没有附加任何对象或使用特殊语法时，`this`通常指向全局对象：

```javascript
function sayHello() {
    console.log(this);
}
sayHello(); // 输出 window 或 global，取决于环境
```



## 普法调用

当函数作为某个对象的方法被调用时，`this`指向该对象：

```javascript
const person = {
    name: "Alice",
    sayName: function() {
        console.log(this.name);
    }
};
person.sayName(); // 输出 "Alice"
```



## 构造函数调用

使用`new`关键字调用函数时，`this`指向新创建的对象：



```javascript
function Person(name) {
    this.name = name;
}

const alice = new Person("Alice");
console.log(alice.name); // 输出 "Alice"
```



## 箭头函数中的 `this`

箭头函数不会创建自己的`this`，而是从封闭作用域继承`this`的值：

```javascript
const obj = {
    name: "Alice",
    sayName: () => {
        console.log(this.name);
    }
};
obj.sayName(); // 输出全局对象的name属性，或undefined，取决于环境
```



## 显式绑定

使用`Function.prototype.call()`、`Function.prototype.apply()`和`Function.prototype.bind()`方法可以显式地设置`this`的值：

```javascript
function sayName() {
    console.log(this.name);
}

const person = { name: "Alice" };

sayName.call(person); // 输出 "Alice"
```



## 严格模式

在严格模式下，全局函数中的`this`以及未绑定的对象方法中的`this`会是`undefined`，而不是全局对象：

```javascript
"use strict";
function sayHello() {
    console.log(this); // 输出 undefined
}
sayHello();
```