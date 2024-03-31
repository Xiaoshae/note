# RTTI

RTTI是运行阶段类型识别(Runtime Type Identification)的简称，旨在为程序在运行阶段确定对象的类型提供一种标准方式。



## 1. dynamic_cast

dynamic_cast用于确定"是否可以安全地将对象的地址赋值给特定类型的指针"。



有三个类：`Grand`，`Superb`和`Magnificent`。

其中，`Superb`是`Grand`的派生类，`Magnificent`是`Superb`的派生类。这就形成了一个类的层次结构。

三个指针：`pg`，`ps`和`pm`，它们分别指向`Grand`，`Superb`和`Magnificent`的实例。



```cpp
class Grand { virtual void func() {} // 虚函数 };
class Superb : public Grand { // ... };
class Magnificent : public Superb { // ... };

// 创建指针
Grand *pg = new Grand;
Grand *ps = new Superb;
Grand *pm = new Magnificent;

// 类型转换
Magnificent *pl = dynamic_cast<Magnificent*>(pm);  // #1
Magnificent *p2 = dynamic_cast<Magnificent*>(pg);  // #2
Superb *p3 = dynamic_cast<Superb*>(pm);            // #3
```



接下来，我们进行了三次类型转换：

1. `Magnificent* pl = (Magnificent*)pm;`（#1）
2. `Magnificent* p2 = (Magnificent*)pg;`（#2）
3. `Superb* p3 = (Magnificent*)pm;`（#3）

现在，我们来分析一下哪些类型转换是安全的。

- 类型转换#1是安全的，因为`pm`实际上指向的是一个`Magnificent`的实例，所以将其转换为`Magnificent*`是没有问题的。
- 类型转换#2是不安全的。虽然语法上允许这样做，但是`pg`实际上指向的是一个`Grand`的实例，而我们试图将其转换为`Magnificent*`。因为`Magnificent`是`Grand`的派生类，所以`Magnificent`可能有一些`Grand`没有的成员。如果我们试图通过`p2`访问这些成员，就会出现问题。
- 类型转换#3是安全的，因为`pm`实际上指向的是一个`Magnificent`的实例，而`Magnificent`是`Superb`的派生类，所以将其转换为`Superb*`是没有问题的。

只有当指针类型与对象的类型相同，或者对象是指针类型的派生类时，类型转换才是安全的。



 dynamic_cast的语法：

```cpp
Superb *pm = dynamic_cast<Superb*>(pg);
```

这行代码的含义是尝试将`pg`指向的对象转换为`Superb*`类型。

转换是合法的，`dynamic_cast`会返回对象的地址，否则，`dynamic_cast`会返回一个空指针。



## 2. typeid

`typeid`运算符可以确定两个对象是否为同种类型，可以接受两种参数：类名或者对象的表达式。

`typeid`运算符返回一个对`type_info`对象的引用，其中，`type_info`是在头文件`typeinfo`中定义的一个类。

`type_info`类重载了`==`和`!=`运算符，以便可以使用这些运算符来对类型进行比较。



如果`pg`指向的是一个`Magnificent`对象，则下述表达式的结果为`bool`值`true`，否则为`false`：

```cpp
typeid(Magnificent) == typeid(*pg)
```

如果`pg`是一个空指针，程序将引发`bad_typeid`异常。该异常类型是从`exception`类派生而来的，是在头文件`typeinfo`中声明的。

注意：typeid是一个运算符，并不是一个函数，不能通过函数来理解typeid引发的异常。



`type_info`类的实现随厂商而异，但包含一个`name()`成员，该函数返回一个随实现而异的字符串：通常（但并非一定）是类的名称。例如，下面的语句显示指针`pg`指向的对象所属的类定义的字符串：

```cpp
cout << "Now processing type " << typeid(*pg).name() << ".\n";
```



## 3. RTTI的应用

```cpp
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <typeinfo>
using namespace std;

class Grand {
private:
    int hold;
public:
    Grand(int h = 0) : hold(h) {
        cout << "I am a grand class!\n";
    }
    virtual void Speak() const {
        cout << "I am a grand class!\n";
    }
    virtual int Value() const {
        return hold;
    }
};

class Superb : public Grand {
public:
    Superb(int h = 0) : Grand(h) {}
    void Speak() const {
        cout << "I am a superb class!!\n";
    }
    virtual void Say() const {
        cout << "I hold the superb value of " << Value() << "!\n";
    }
};

class Magnificent : public Superb {
private:
    char ch;
public:
    Magnificent(int h = 0, char cv = 'A') : Superb(h), ch(cv) {}
    void Speak() const {
        cout << "I am a magnificent class!!!\n";
    }
    void Say() const {
        cout << "I hold the character " << ch << " and the integer " << Value() << "!\n";
    }
};

Grand* GetOne() {
    Grand* p = NULL;
    switch (rand() % 3) {
    case 0:
        p = new Grand(rand() % 100);
        break;
    case 1:
        p = new Superb(rand() % 100);
        break;
    case 2:
        p = new Magnificent(rand() % 100, 'A' + rand() % 26);
        break;
    }
    return p;
}

int main() {
    srand(time(0));
    Grand* pg;
    Superb* ps;
    for (int i = 0; i < 5; i++) {
        pg = GetOne();
        cout << "Now processing type " << typeid(*pg).name() << ".\n";
        pg->Speak();
        if (ps = dynamic_cast<Superb*>(pg)) {
            ps->Say();
        }
        if (typeid(Magnificent) == typeid(*pg)) {
            cout << "Yes, you're really magnificent.\n";
        }
    }
    return 0;
}
```

---

`Grand`类定义了一个虚函数`Speak()`，`Superb`类和`Magnificent`类都重写了这个函数。

直接通过`Grand*`类型的指针`pg`来调用`Speak()`，而不需要知道`pg`指向的具体类型：

```cpp
pg->Speak();
```



`Superb`类定义了`Say()`函数，其派生类都会继承（或重写）这个函数。

所以以下代码适用于所有从`Superb`派生而来的类：

```cpp
if (ps = dynamic_cast<Superb*>(pg)) {
    ps->Say();
}
```

如果`pg`实际上指向的对象是`Superb`类的实例或其派生类的实例，那么这个转换就是合法的，`dynamic_cast`会返回对象的地址。否则，`dynamic_cast`会返回一个空指针。

如果`ps`非空（即转换成功），就会调用`ps->Say()`。



`typeid(Magnificent)`和`typeid(*pg)`都会返回一个`std::type_info`对象的引用，这个对象包含了类型信息。

如果`pg`指向的对象的类型是`Magnificent`，那么`typeid(Magnificent)`和`typeid(*pg)`返回的`type_info`对象是相同的。

所以`typeid(Magnificent) == typeid(*pg)`的结果为`true`，就会打印出"Yes, you’re really magnificent."。

```cpp
if (typeid(Magnificent) == typeid(*pg)) {
    cout << "Yes, you're really magnificent.\n";
}
```

如果`pg`指向的对象的类型不是`Magnificent`，那么`typeid(Magnificent) == typeid(*pg)`的结果为`false`，就不会打印出任何东西。

