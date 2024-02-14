## switch

switch 语句是一种多路分支控制结构，它允许程序根据一个表达式的值来决定执行哪个代码块。基本语法如下：

```
switch (integer-expression) {
    case label1:	statement(s);
    case label2:	statement(s);
    // ...
    default:		statement(s);
}
```



在 switch 语句中，首先会计算 integer-expression （必须是一个整数或枚举类型的表达式）的值，然后与每个 case 标签的值进行比较。

如果找到了与 integer-expression 的值相等的 case 标签（一个整数常量或枚举量），那么程序就会从这个 case 开始执行，直到遇到 break 语句（或switch结束）。

如果没有找到与 integer-expression 的值相等的 case 标签，那么程序就会执行 default 代码块（default是可选的）。



### 将枚举量用作标签

```cpp
#include <iostream>

// 创建名为 Color 的枚举，包含 7 个枚举量
enum Color { red, orange, yellow, green, blue, violet, indigo };

int main() {
    using namespace std;
    cout << "Enter color code (0-6): ";
    int code;
    cin >> code;

    // 当输入的代码在枚举范围内时，执行 switch 语句
    while (code >= red && code <= indigo) {
        switch (code) {
            case red:
                cout << "Her lips were red.\n";
                break;
            case orange:
                cout << "Her hair was orange.\n";
                break;
            case yellow:
                cout << "Her shoes were yellow.\n";
                break;
            case green:
                cout << "Her nails were green.\n";
                break;
            case blue:
                cout << "Her sweatsuit was blue.\n";
                break;
            case violet:
                cout << "Her eyes were violet.\n";
                break;
            case indigo:
                cout << "Her mood was indigo.\n";
                break;
        }
        cout << "Enter color code (0-6): ";
        cin >> code;
    }
    cout << "Bye\n";
    return 0;
}

```

