# if

## 1. 基本的 if 语句

基本的 `if` 语句的格式如下：

```c++
if (条件表达式) {
    // 条件为 true 时执行的代码
}
```



如果条件表达式的值为 `true`，则执行大括号 `{}` 内的代码。如果条件表达式的值为 `false`，则跳过大括号内的代码。

例如，下面的代码会检查 `x` 是否大于 `y`：

```c++
if (x > y) {
    cout << "x is greater than y." << endl;
}
```



## 2. if-else 语句

`if-else` 语句允许你在条件为 `false` 时执行一些代码。它的格式如下：

```c++
if (条件表达式) {
    // 条件为 true 时执行的代码
} else {
    // 条件为 false 时执行的代码
}
```



例如，下面的代码会检查 `x` 是否大于 `y`，如果 `x` 大于 `y`，则输出 “x is greater than y.”，否则输出 “x is not greater than y.”：

```c++
if (x > y) {
    cout << "x is greater than y." << endl;
} else {
    cout << "x is not greater than y." << endl;
}
```



## 3. if-else if-else 语句

`if-else if-else` 语句允许你根据多个条件来选择执行哪些代码。它的格式如下：

```c++
if (条件表达式1) {
    // 条件表达式1 为 true 时执行的代码
} else if (条件表达式2) {
    // 条件表达式1 为 false，且条件表达式2 为 true 时执行的代码
} else {
    // 所有条件表达式都为 false 时执行的代码
}
```



例如，下面的代码会检查 `x`、`y` 和 `z` 的大小关系：

```c++
if (x > y && x > z) {
    cout << "x is the greatest." << endl;
} else if (y > x && y > z) {
    cout << "y is the greatest." << endl;
} else {
    cout << "z is the greatest." << endl;
}
```



