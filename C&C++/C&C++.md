

# string 类

`string`类是ISO/ANSI C++98标准的一部分，它提供了一种更简单、更安全的方式来处理字符串，相比于传统的字符数组。

`string`类位于名称空间`std`中，因此你需要使用`using`编译指令，或者使用`std::string`来引用它。



1. 你可以使用C风格字符串来初始化`string`对象。

    `string str = "Hello, World!";`

2. 你可以使用数组表示法来访问存储在`string`对象中的字符。

    char c = str[0];`。

3. `string`对象可以声明为简单变量，而不是数组。

    `string str;`

4. 当你将输入读取到`string`对象中时，`string`对象会自动调整其大小以适应输入。



```C++
char first_date[] =		{"Le Chapon Dodu"};
char second_date[] =	{"The Elegant Plate"};
string third_date =		{"The Bread Bowl"};
string fourth_date		{"Hank's Fine Eats"}; //这里没有 = 
```



## 赋值、拼接和附加

1. **赋值**：在C++中，不能将一个数组赋给另一个数组，但可以将一个`string`对象赋给另一个`string`对象。例如：

```cpp
char charr1[20]; // 创建一个空数组
char charr2[20] = "jaguar"; // 创建一个初始化的数组
string str1; // 创建一个空的string对象
string str2 = "panther"; // 创建一个初始化的string对象

charr1 = charr2; // 无效，不允许数组赋值
str1 = str2; // 有效，允许对象赋值
```



1. **拼接和附加**：`string`类简化了字符串合并操作。你可以使用运算符`+`将两个`string`对象合并起来，也可以使用运算符`+=`将字符串附加到`string`对象的末尾。例如：

```cpp
string str3;
str3 = str1 + str2; // 将str1和str2拼接后赋值给str3
str1 += str2; // 将str2附加到str1的末尾
```



## 字符串输入与输出

暂略



## 其他形式的字符串字面值

除了`char`类型外，C++还有`wchar_t`类型，C++11新增了`char16_t`和`char32_t`类型，使用前缀`L`、`u`和`U`表示。

```C++
wchar_t title[] = L"Chief Astrogator"; // wchar_t string
char16_t name[] = u"Felonia Ripova"; // char16_t string
char32_t car[] = U"Humber Super Snipe"; // char32_t string
```



原始字符串是C++11新增的一种字符串类型。在原始字符串中，字符表示的就是自己。

例如，序列`\n`不表示换行符，而表示两个常规字符——斜杠和n。

因此在屏幕上显示时，将显示这两个字符。另一个例子是，可以在字符串中使用双引号`"`, 而无需像以前那样使用转义字符`\"`。

由于在原始字符串中可以包含双引号`"`, 因此不能再使用它来表示字符串的开头和末尾。因此，原始字符串使用`"(和)"`作为定界符，并使用前缀`R`来标识原始字符串。例如：

```cpp
cout << R"(Jim "King" Tutt uses "\n" instead of endl.)" << '\n';
```

这段代码将在屏幕上显示以下内容：

```cpp
Jim "King" Tutt uses "\n" instead of endl.
```



原始字符串使用`"(和)"`作为定界符，并使用前缀`R`来标识原始字符串。

如果要在原始字符串中包含`)"`，可以在表示字符串开头的`"`和`(`之间添加其他字符，这意味着表示字符串结尾的`"`和`)`之间也必须包含这些字符。



例如，使用`R"+*(`标识原始字符串的开头时，必须使用`)+*"`标识原始字符串的结尾。

```cpp
cout << R"+*("(Who wouldn't?)", she whispered.)+*" << endl;
```

它会在屏幕上显示以下内容：

```cpp
"(Who wouldn't?)", she whispered.
```













# 模板类vector

模板类`vector`是一种动态数组，类型于`string`，长度可以在运行阶段设置，可以在末尾附加新数据，也可以在中间插入新数据。

实际上，`vector`类使用`new`和`delete`来管理内存，但这种工作是自动完成的。



包含头文件`vector`，`vector`包含在名称空间`std`中，可以使用`using`编译指令：

```cpp
#include <vector>
using std::vector;
```





模板使用不同的语法来指出它存储的数据类型。

例如，`vector<int>`对象存储的是`int`类型的数据，`vector<double>`对象存储的是`double`类型的数据。

`vector<double> vd(n);`创建了一个包含`n`个`double`类型元素的`vector`对象。

插入或添加值时会自动调整长度，因此可以将`vector`对象的初始长度设置为零。

```cpp
std::vector<int> v;  // 创建一个空的vector

// 使用push_back()添加元素
// 此方法可以在末尾添加一个元素，同时vector的长度会自动增加1。
v.push_back(1);

// 使用pop_back()删除元素
// 此方法可以删除最后一个元素，同时vector的长度会自动减少1。
v.pop_back();

// 使用resize()设置长度
// 此方法可以直接设置vector的长度。
v.resize(5);
```



# 类模板array

`array`是一个模板类，它提供了一种更安全、更方便的方式来创建和使用固定长度的数组。

与传统的数组一样，`array`对象的长度是固定的，它使用栈（静态内存分配），而不是自由存储区，因此其效率与数组相同，但更方便，更安全。



要使用`std::array`，你需要包含头文件，并使用using指令：

```cpp
#include <array>
using std:array;


```



语法格式：`std::array<type, size> variable_name;`

其中`type`是元素的类型，`size`是数组的大小（元素的数量，此处不能为变量），`variable_name`是变量名。

```cpp
array<int,10> tc;
```





































# 类



## 类和对象概述

​	什么是类？什么是对象？可以这么理解，类指的是一类特征，比如胖子，他的特征是埃、胖、油腻等。而对象是一个具体的实体，例如：小明，这样一个实实在在的人。



在C++中，使用 `class book { ... }` 声明的一种类型，将其称作一个类。在使用 `book English;` 定义的一个变量，将其称作一个对象。



## 类声明



## 公有(public)和私有(private)

类的设计尽可能将**公有接口和实现细节分开**，即用户只需要通过**调用公有接口**就可以**实现特定的功能**，而**不需要去考虑该功能是如何实现**的。**public**(公有部分)的变量和函数，是使用该类的程序员可以**直接访问**的，**private**(私有部分)的变量和函数，程序员**无法直接访问**，只能通过**调用公有部分的接口**(函数)进行**间接访问**。



在下面程序中，用户可以直接访问Book中的Name变量，而不能直接访问CreationTime变量，必须通过GetTime来间接访问CreationTime变量。

```c++
class Book {
private:
    long long int CreationTime;

public:
	string Name;
	double value;
	float discount;
	
	double GetPrice(void){
		
		return value / discout;
	
	}
    
	long long int GetTime(void){
        
        return this->CreationTime;
        
    }

}
```



### 类成员函数

除了上面直接在class声明中定义成员函数，也可以只在class中进行声明，在其他地方定义，使用作用域解析运算符(**::**)来标识函数所属的类。

```C++
class Book{
public:
	...
	double GetPrice(void); //声明
	...
}

double Book::GetPrice(void){
	
	return value / discout;  //定义
	
}
```



### 内联函数

直接在类中定义的函数会自动成为内联函数，在类声明中，常将代码段小的函数作为内联函数，例如在下面的例子中，`Book::GetPric()`是一个内联函数。

```c++
class Book{
public:
	...
	double Book::GetPrice(void){
	
		return value / discout;
	
	}
	...
}


```



通过`inline`限定符可以使在外部定义的成员函数成为内联函数。

```c++
class Book{
public:
	...
	double GetPrice(void); //声明
	...
}

//inline限定符
inline double Book::GetPrice(void){
	
	return value / discout;  //定义
	
}
```



内联函数的特殊规则要求，在每个使用它们的文件中都对其进行定义。最简便的方法是：将内联定义放在定义类的头文件中(有些开发系统包含智能链接程序，允许将内联定义放在一个独立的实现文件)。然后在每个使用该内联函数的源程序中包含整个头文件。

根据改写规则(rewrite rule)，在类声明中定义方法，等同于用原型替换方法定义，然后在类声明的后面将定义改写为内联函数。（**这里暂时还不理解**）。



## 存储空间

创建的每个新对象都有自己的存储空间，用于存储其内部变量和类成员;但同一个类的所有对象共享同一组类方法，即每种方法只有一个副本。例如，假设 `kate` 和 `joe` 都是 `Stock` 对象，（shares是类中的变量）则 `kate.shares` 将占据一个内存块，而 `joe.shares` 占用另一个内存块，（show()是类中的函数）但 `kate.show()` 和 `joe.show()` 都调用同一个方法，也就是说，它们将执行同一个代码块，只是将这些代码用于不同的数据。



## 析构函数



