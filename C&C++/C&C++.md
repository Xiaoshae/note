

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

根据改写规则(rewrite rule)，在类声明中定义方法，等同于用原型替换方法定义，然后在类声明的后面将定义改写为内联函数。

## 存储空间

创建的每个新对象都有自己的存储空间，用于存储其内部变量和类成员;但同一个类的所有对象共享同一组类方法，即每种方法只有一个副本。例如，假设 `kate` 和 `joe` 都是 `Stock` 对象，（shares是类中的变量）则 `kate.shares` 将占据一个内存块，而 `joe.shares` 占用另一个内存块，（show()是类中的函数）但 `kate.show()` 和 `joe.show()` 都调用同一个方法，也就是说，它们将执行同一个代码块，只是将这些代码用于不同的数据。



## 构造函数

构造函数用于在创建对象时进行初始化，在创建对象后则无法调用构造函数。

构造函数的名称与类名称相同，且没有返回值。



### 默认的构造函数

在没有创建任何构造函数时，则存在一个默认的构造函数，其形式如下：

```cpp
class Book {

public:
	 
	string name;
	double value;
	int number;

	Book(void){ };

};
```



### 定义构造函数

定义一个构造函数，该函数接受三个变量，用于给类中的变量进行初始化：

```cpp
class Book {

public:
	 
	string name;
	double value;
	int number;
	
	Book(string newName, double newValue, int newNumber) {

		this->name = newName;
		this->value = newValue;
		this->number = newNumber;

	}

};
```



### 默认构造函数

默认构造函数，当一个构造函数不需要提供参数时，那么它就是一个构造函数：

例如：该下面两个都是默认构造函数，虽然第一个构造函数有三个参数，但他们是可选的。

```cpp
Book(string newName = "", double newValue = 0.0 int newNumber = 0) {

		this->name = newName;
		this->value = newValue;
		this->number = newNumber;

}

Book(void) {

	this->name = "";
	this->value = 0.0;
	this->number = 0;

}
```



### 调用构造函数

调用构造函数：在创建一个对象时没有提供任何的参数，则会调用默认构造函数，如果有多个构造函数（如有上面两个构造函数）则会报错。

```cpp
Book english; //调用默认构造函数

//显示的使用默认构造函数
Book english = Book();
Book english();
Book english {};

//以下几种提供参数的方法都可以，调用非默认构造函数：
Book english = Book("english",10.0,5);
Book english("english",10.0,5);
Book english {"english",10.0,5};
```



### 异常情况

创建了任意一个构造函数，编译器就不会提供默认构造函数了。如果只手动创建了带参数的构造函数，而没有创建默认构造函数，则可能会出现以下情况：

```cpp
class Book {

public:
	 
	string name;
	double value;
	int number;
	
	Book(string newName, double newValue, int newNumber) {

		this->name = newName;
		this->value = newValue;
		this->number = newNumber;

	}

};

//以下几种提供参数的方法都可以：
Book english = Book("english",10.0,5);//调用Book(string newName, double newValue, int newNumber)构造函数
Book english("english",10.0,5);
Book english {"english",10.0,5};

//以下几种情况，都没有提供任何参数，会调用默认构造函数
Book english;//在定义对象时，没有提供任何参数，也没有手动定义任何默认构造函数，编译器找不到默认构造函数，会报错
Book english = Book();
Book english();
Book english {};
```



## 析构函数

析构函数用于在对象声明周期到期时自动调用，一般用于释放new分配的内存空间，析构函数一般为空。



析构函数的名称为`~`加`类名`，例如：类名为`Book`，则析构函数的名称为`~Book`。

析构函数没有返回类型，也不能有参数，这意味着析构函数只有一个，不能进行函数重载。

如果没有手动定义析构函数，则编译器会提供默认的析构函数（不进行任何操作）。



### 默认的析构函数

```cpp
class Book {

public:
	 
	string name;
	double value;
	int number;
	
	~Book(void){ }
};
```



### 定义析构函数

只需要定义一个名称为`~`加`类名`的函数就可以了。

```cpp
class Book {

public:
	 
	string * name;
	double value;
	int number;
	
	Book(void){
		//构造函数中使用new分配了内存
		this->name = new string;
		this->value = 0.0;
		this->number = 0;
		
	}
	
	~Book(void){
		//析构函数中使用delete释放new分配的内存
		delete this->name;
	}
};
```



## 初始化对象

以下几种初始化的方法有什么不同呢？

```
Book english;
Book english = Book("english",10.0,0);
Book english();
Book english("english",10.0,0);
Book english {};
```



首先判断这两个：

`Book english("english",10.0,0);`：创建一个对象，隐示的传递参数调用构造函数

`Book english();`：这是一个函数声明，声明一个没有参数，**返回值类型为`Book`类型的函数**。



`Book english = Book();`：创建临时Book对象，这个临时Book类型使用**默认构造函数进行构造**，构造完成后赋值给english对象。

`Book english = Book("english",10.0,0);`：创建临时Book对象，**使用提供的参数进行构造**，构造完成后赋值给english对象。

注意：english对象不会调用构造函数，而是创建临时对象，等临时对象构造完成，将临时对象中的内容赋值到english对象中。

编译器可能立刻删除临时对象，但也可能会等一段时间，在这种情况下，临时对象的析构函数要过一会才会被调用。



如果采用以下方式，则会出现调用两次析构函数的情况：

```
Book english;
english = Book("english",10.0,0);
```

第一条语句，定义english对象时，使用默认构造函数进行构造。

第二条语句，这实际上时一条赋值语句，定义临时Book类型变量，对临时变量进行构造会调用一次构造函数，构造完成后将临时变量中的内容赋值给english变量。



这两种情况没有什么区别，但是请注意（列表初始化不允许降低精度）：

```
Book english("english",10.0,0);
Book english {"english",10.0,0};
```



## const成员函数

如果在定义一个对象时，使用了const限定符，那么不能直接使用类成员函数，因为类成员函数无法确保对象不被修改。

```cpp
ConstStock land = Stock("Kludgehorn Properties");
land.show(); //编译器会拒绝这一行
```



C++的解决方法是将 const 关键字放在函数的括号后面，告知编译器该函数保证函数不会修改调用对象。

`show()`声明应像这样:

```cpp
void show() const;
```

函数定义的开头应像这样:

```cpp
void stock::show() const{
	...
}
```



## this指针

this 指针指向用来调用成员函数的对象(this被作为隐藏参数传递给方法)。

在函数的括号后面使用 const 限定符将 this 限定为 const,这样将不能使用 this 来修改对象的值。

 this 是对象的地址，`*this`(将解除引用运算符`*`用于指针，将得到指针指向的值)是对象本身。

```cpp
class Book {

public:
	 
	string * name;
	double value;
	int number;
	
	string Get_name(void) const{
		
		// *this对象本身
		// this 指向对象的指针
		// *this.name 对象中的name变量
		// this->name 指针需要通过->来访问，和结构体一样
		// this->value = 10; 在const函数中被禁止，在非const函数中允许
		
        return this->name;
        
	}
};
```

