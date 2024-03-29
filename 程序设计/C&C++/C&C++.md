

# string 类

`string`类是ISO/ANSI C++98标准的一部分，它提供了一种更简单、更安全的方式来处理字符串，相比于传统的字符数组。

`string`类位于名称空间`std`中，因此你需要使用`using`编译指令，或者使用`std::string`来引用它。



1. 你可以使用C风格字符串来初始化`string`对象。

    `string str = "Hello, World!";`

2. 你可以使用数组表示法来访问存储在`string`对象中的字符。

    `char c = str[0];`。

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

```cpp
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

```cpp
Book english;
english = Book("english",10.0,0);
```

第一条语句，定义english对象时，使用默认构造函数进行构造。

第二条语句，这实际上时一条赋值语句，定义临时Book类型变量，对临时变量进行构造会调用一次构造函数，构造完成后将临时变量中的内容赋值给english变量。



这两种情况没有什么区别，但是请注意（列表初始化不允许降低精度）：

```cpp
Book english("english",10.0,0);
Book english {"english",10.0,0};
```



注意：假设已经有了一个对象，将其直接赋值给另一个对象，虽然该对象不会调用构造函数，但是不要忘了该对象生命周期结束时，还是会调用析构函数。

```cpp
Book english {"english",10.0,0};
Book chinese = english;
```

在上面这里例子中，只有english对象会调用构造函数，但是english和chinese都会调用析构函数。



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



## 对象数组

声明对象数组的方法与声明标准类型数组相同：

```cpp
Book mystuff[2];
```

创建了2个mystuff对象，分别为mystuff[0]、mystuff[1]

每一个对象都会调用构造函数，由于没有提供参数，会调用默认构造函数，该语句会导致2次构造函数的调用。



### 初始化对象数组

```cpp
Book mystuff[2] = {
	Book("english",10.0,5),
	Book("chinese",20.0,6)
}

Book mystuff[2] = {
    {"english",10.0,5},
    {"chinese",20.0,7}
}
```



# 类作用域

在类中定义的名称(如类数据成员名和类成员函数名)的作用域都为整个类，作用域为整个类的名称只在该类中是已知的，在类外是不可知的。



不能从外部直接访问类的成员和公有成员函数，必须通过对象：

```cpp
Book english;
cout << english.name << endl;
english.display();
```



在定义成员函数时，必须使用作用域解析运算符：

```cpp
void Book::update(double price){
	...
}
```



在类声明或成员函数定义中，可以直接使用成员的名称，无需任何修饰。例如，在类的成员函数`sel()`中可以直接调用另一个成员函数`set_tot()`。

**成员运算符的使用**：在其他情况下，访问类的成员需要使用特定的运算符：

- **直接成员运算符(.)**：当对象是实体（非指针）时，使用`.`来访问其成员。
- **间接成员运算符(->)**：当对象是指针时，使用`->`来访问其成员。
- **作用域解析运算符(::)**：用于访问类的静态成员，或者在类外部访问类的成员。



## 静态类成员

在类中，不能直接定义一个常量并给它赋值，因为类的定义只是一个模板，它并没有创建任何实际的对象，所以没有地方存储这个常量的值。例如，下面的代码是错误的：

```cpp
class Book {

public:
	 
	 const int length = 10;	// 这是不允许的

};
```



静态类成员与其他静态变量存储在一起，而不是存储在对象中，所以可以静态类成员是可以有初始值的，例如：

```cpp
class Book {

public:
	 
	 static const int length = 10;	// 这是允许的， 因为前面加了static变成了静态类常量

};
```



## 类中使用枚举

枚举在类中的作用域是整个类，所以我们可以用枚举来为整个类提供一个常量。例如：

```cpp
class Bakery {
private:
    enum { Months = 12 };
    double costs[Months];
};
```

`Months` 是一个符号名称，它在整个类的作用域内都可以使用，并且编译器会自动用 `12` 来替换它。

这种方式并不会在类中创建一个数据成员，也就是说，所有的对象都不包含这个枚举（指这个枚举不会占用对象的存储空间）。



## 枚举类

C++11引入了一种新的枚举类型，称为限定作用域的枚举类型（scoped enumeration），也被称为枚举类（enum class）。这种新的枚举类型解决了传统枚举类型的一些问题，并提供了更好的类型安全性和可读性。

以下是限定作用域的枚举类型的定义方式：

```cpp
enum class Color {Red, Green, Blue};
```



- 作用域：限定作用域的枚举类型的枚举值被限定在特定的作用域内，需要通过作用域解析操作符::来访问。例如，Color::Red。
- 类型安全：限定作用域的枚举类型是类型安全的，不能隐式地转换为其它类型，这有助于避免意外的错误。
- 命名冲突：在不同的作用域中可以使用相同的枚举值而不会发生命名冲突。



这是一个使用限定作用域的枚举类型的例子：

```cpp
enum class Color {Red, Green, Blue};
Color myColor = Color::Red;
```

Color::Red是一个枚举值，它在Color的作用域内。你不能直接使用Red，必须使用Color::Red。



不能将Color::Red隐式地转换为一个整数，整形运算和关系运算符都不能有枚举类：

```cpp
int x = Color::Red; // 不被允许的
if( Color::Red > 10) { ... }  //不被允许的
```



如果需要将其转换为一个整数，你必须使用强制类型转换：

```cpp
int x = int(Color::Red);
int y = int(Color::Red) + x + 10;
```



# 类高级操作

## 运算符重载

`operator运算符()`，使用`operator` + `运算符` + `()`即可重载一个指定的运算符。例如`operator+()`就是重载了`+`运算符。

例如，假设有一个 `Salesperson` 类，并为它定义了`operatot+()`成员函数，以重载`+`运算符，以便能够将两个 Saleperson对象的销售额相加。

则如果 district2、sid 和 sara都是 Salesperson 类对象，便可以编写这样的等式：

```cpp
district2 =sid + sara;
```

编译器发现，操作数是 Salesperson 类对象，因此使用相应的运算符函数替换上述运算符

```cpp
district2 =sid.operator+(sara);
```



```cpp
Time Time::operator+(const Time &t) const {
    Time sum;
    sum.minutes = minutes + t.minutes;
    sum.hours = hours + t.hours + sum.minutes / 60;
    sum.minutes %= 60;  // 修复：分钟数应在0到59之间
    return sum;
}
```

参数是可以是引用，但返回类型却不是引用。将参数声明为引用的目的是为了提高效率。如果按值传递Salesperson对象，代码的功能将相同，但传递引用，速度将更快，使用的内存将更少。

返回值不能是引用。因为函数将创建一个新的 Time对象，来表示另外两个 Time 对象的和。返回对象(如代码所做的那样)将创建对象的副本，而调用函数可以使用它。然而，如果返回类型为Time &，则引用的将是 sum 对象。但由于 sum 对象是局部变量，在函数结束时将被删除，因此引用将指向一个不存在的对象。使用返回类型 Time 意味着程序将在删除 sum 之前构造它的拷贝，调用函数将得到该拷贝。

`t4 = t1 + t2 + t3;`是有效的，它会被转换为：

```cpp
t4 = t1.operator+(t2 + t3);
t4 = t1.operator+(t2.operator+(t3));
```



## 重载限制

1. **重载后的运算符必须至少有一个操作数是用户定义的类型**：这将防止用户为标准类型重载运算符。因此，不能将减法运算符(-)重载为计算两个double值的和，而不是它们的差。虽然这种限制将对创造性有所影响，但可以确保程序正常运行。
2. **使用运算符时不能违反运算符原来的句法规则**：例如，不能将求模运算符(%)重载成使用一个操作数。同样，不能修改运算符的优先级。因此，如果将加号运算符重载成将两个类相加，则新的运算符与原来的加号具有相同的优先级。
3. **不能创建新运算符**：例如，不能定义`operator**()`函数来表示求幂。不能重载下面的运算符：
    - `sizeof`：sizeof运算符
    - `.`：成员运算符
    - `*`：成员指针运算符
    - `::`：作用域解析运算符
    - `?::`：条件运算符
    - `typeid`：一个RTTI运算符
    - `const_cast`：强制类型转换运算符
    - `dynamic_cast`：强制类型转换运算符
    - `reinterpret_cast`：强制类型转换运算符
    - `static_cast`：强制类型转换运算符
4. **表11.1中的大多数运算符都可以通过成员或非成员函数进行重载**，但下面的运算符只能通过成员函数进行重载：
    - 赋值运算符
    - 函数调用运算符
    - 下标运算符
    - 通过指针访问类成员的运算符



## 友元函数

如果将一个成员变量或者函数设置为私有，则只能在其他成员函数中访问，而无法通过其他函数访问，例如：

```cpp
class Time {
private:
	int length;
	void show_length(void) {
		cout << this->length << endl;
	}

public:
	int hour;
	int minutes;

	void show_time(void) {
		cout << this->hour << endl;
		cout << this->minutes << endl;
	}
};

int main(void) {
	Time test;

	test.hour = 10;
	test.minutes = 50;
	
	test.show_time();

	test.length = 10;
	test.show_length();
}
```

hour、minutes以及show_time()都是公有部分可以在其他函数中访问，而length和show_length()是私有部分，无法再非成员函数中访问。



如果想要在非成员函数中访问私有变量，则需要将这个函数声明为友元函数，例如：

```cpp
class Time {
private:

	int length;

	void show_length(void) {

		cout << this->length << endl;

	}

public:

	int hour;
	int minutes;

	void show_time(void) {
		
		cout << this->hour << endl;
		cout << this->minutes << endl;

	}
	
    //声明友元函数，在函数原型前面加上friend关键字
	friend void show_all(Time& show_time);

};

//定义友元函数 此处不能有friend关键字
void show_all(Time& display) {

	display.hour = 10;
	display.minutes = 30;
	display.show_time();

	display.length = 25;
	display.show_length();

	return;
}

int main(void) {

	Time test;
	show_all(test);

}
```

首先在类外部定义了一个函数，，由于该函数非类中成员函数，所以无需使用`::`类限定符。

```cpp
void show_all(Time& display){}			// 友元函数的定义
void Time::show_all(Time& display){}	// 类成员函数的定义
```

在类外部定义的函数不能有friend关键字，然后需要在类中进行声明，在函数原型前面加上friend关键字。

如果该函数需要访问多个类的私有成员，则必须在每一个类中使用friend声明为友元函数。

将友元函数声明在公有部分还是私有部分，对友元函数的访问权限没有影响，通常会将友元函数声明在公有部分，这样可以清楚地表明这个函数是类的一个接口。



如果想要将友元函数定义在类中，指向在定义前面加上`friend`关键字就可以了：

```cpp
class Time{

public:
	
	void show_time(void){	// 定义在类中的成员函数
		/* ... */
	}
	
	friend show_all(void){	// 定义在类中的友元函数
		/* ... */
	}

}
```



## 非成员函数的运算符重载

非成员函数的运算符重载通常用于实现那些至少有一个操作数不是用户定义类型的运算符。

假设现在有以下定义：

```cpp
Time Time::operator+(int minutes) const {
    Time sum;
    sum.minutes = minutes + t.minutes;
    sum.hours = hours + t.hours + sum.minutes / 60;
    sum.minutes %= 60;  // 修复：分钟数应在0到59之间
    return sum;
}
```

此时，并不是将两个Time类型相加，而是将一个Time类型和一个int类型相加。

如果通过以下方法使用该运算符重载，则可以正常识别：

```cpp
Time temp,day;
temp  = day + 10;
```

它会被转换为：

```cpp
temp = day.operator+(10)；
```

但如果使用这种方式，则无法正常识别：

```cpp
Time temp,day;
temp  = 10 +day;
```



所以可以使用非成员函数的运算符重载（由于不是成员函数，则在定义时可以不需要Time::）：

```cpp
Time operator+(int minutes,Time & time_min) const {
    Time sum;
   	/* ... */
    return sum;
}
```

如果在非成员函数的运算符重载中访问了类的私有部分，则必须将该函数设定为友元函数，如果没有访问公有部分，则可以不设置为友元函数。

将该函数作为友元也是一个好主意。最重要的是，它将该作为正式类接口的组成部分。其次，如果以后发现需要函数直接访问私有数据，则只要修改函数定义即可，而不必修改类原型。



 ## 重载 << 运算符

假设 trip 是一个 Time 对象。为显示 Time 的值，前面使用的是 Show()。然而，如果可以像下面这样探作将更好：

```cpp
cout <<trip;
```

<< 是可以重载的运算符之一，所以可以通过运算符重载来实现上面的功能。



如果使用一个 Time 成员函数来重载 << ，Time 对象将是第一个操作数，就像使用成员函数重载*运算符那样。

这意味着必须这样使用：

```cpp
trip << cout;
```

这样会令人迷惑。



通过使用友元函数，可以像下面这样重载运算符：

```cpp
ostream& operator<<(ostream &os, const Time &t) {
    os << t.hours << " hours, " << t.minutes << " minutes";
    return os;
}
```

在上面的运算符重载函数中，只需要设置为Time类的友元函数，因为它使用了Time类中的两个私有成员变量（hours和minutes，假设它们是），而不需要设置为ostream的友元函数，因为在运算符重载函数中没有使用ostream类的私有变量，而是使用了整个对象。

为什么要将返回值类型设置为`ostream&`呢？

在理解 `cout` 操作之前，我们先看下面的语句：

```cpp
int x = 5;
int y = 8;
cout << x << y;
```

`iostream` 要求`<<` 运算符要求左边是一个 `ostream` 对象，因为 `cout` 是 `ostream` 对象，所以表达式 `cout << x` 满足这种要求。

因为表达式 `cout << x` 位于 `<< y` 的左侧，所该表达式（`cout << x`）执行完毕后必须是一个 `ostream` 类型的对象，因此，`ostream` 类将 `operator<<()` 函数实现为返回一个指向 `ostream` 对象的引用。



这样可以使用下面的语句：

```cpp
cout << "Trip time:" << trip << "(Tuesday)\n" ;
```

最后它们被转换为：

```cpp
((cout.operator<<("Trip time:")).operator<<(trip)).operator<<("(Tuesday)\n");
```



## 成员函数和友元函数如何选择

以下是两者的主要区别：

- 当重载为**成员函数**时，会隐含一个this指针；
- 当重载为**友元函数**时，不存在隐含的this指针，需要在参数列表中显示地添加操作数。

建议：

- 单目运算符中`=、()、[]、->`只能作为成员函数
- 单目运算符中运算符`+=、-=、/=、*=、&=、!=、~=、%=、<<=、>>=`建议重载为成员函数。
- 其他运算符，建议重载为友元函数。



## 转换函数（to类）

只接受一个参数的构造函数可以作为转换函数。

例如，如果有一个类Stonewt，并且它有一个接受double类型参数的构造函数：

```cpp
Stonewt(double lbs);
```

用于将 double 类型的值转换为 Stonewt 类型：

```cpp
Stonewt myCat;
myCat = 19.6;
```

C++新增了关键字 explicit,用于关闭这种自动特性：

```cpp
explicit Stonewt(double lbs);
```

现在只能通过强制类型转换将double类型的值转换为Stonewt类型的对象：

```cpp
// 创建一个 Stonewt 对象
Stonewt myCat;

// 下面的代码将会报错，因为我们已经禁止了隐式转换
// myCat = 19.6;
// Stonewt myCat = 19.6;

// 显式强制类型转换，这是允许的
myCat = Stonewt(19.6);

// 旧式的显式类型转换，这也是允许的
myCat = (Stonewt)19.6;
```



如果在声明中使用了关键字explicit，则Stonewt(double)将只用于显式强制类型转换，否则还可以用于下面的隐式转换：

- 将 Stonewt对象初始化为 double 值时。
- 将 double 值赋给 Stonewt 对象时。
- 将 double 值传递给接受 Stonewt参数的函数时。
- 返回值被声明为 Stonewt的函数试图返回 double 值时。在上述任意一种情况下，使用可转换为double类型的内置类型时。



仅当转换不存在二义性时，才会进行这种二步转换。

如果这个类还定义了构造函数 Stonewt(long)，则编译器将拒绝这些语句，可能指出：int可被转换为long或 double，因此调用存在二义性。



以下情况也可以出现二义性：

```cpp
Time(int hour = 0, int minutes = 0);

Time(int hour_new);
```



如果给任意一个加上explicit关键字，就没有二义性了：

```cpp
explicit Time(int hour = 0, int minutes = 0);

Time(int hour_new);
```





## 转换函数

将用户自定义的类型，要转换为typeName 类型，需要使用这种形式的转换函数:

```cpp
operator typeName();
```

请注意以下几点：

- 转换函数必须是类方法（成员函数）；
- 转换函数不能指定返回类型；
- 转换函数不能有参数。

例如，转换为 double 类型的函数的原型如下:

```cpp
operator double();
```



二义性

假设定义了从Stonewt到double或int的类型转换：

```cpp
operator double(void);
operator int(void);
```



将Stonewt赋值long，int 和 double 值都可以被赋给 long 变量，存在二义性，编译器会报错：

```cpp
Stonewt temp;
long number = temp; // 非法的
long number = int(temp);		//合法
long number = long(temp);		//合法
```



假设现在没有为Stonewt重载<<运算符，需要转换为基类才能使用ostream进行输出：

cout既可以输出int，又可以输出double，也会出现二义性。

```cpp
Stonewt temp;
cout << temp << endl;				// 非法的
cout << int(temp) << endl;			//合法
cout << double(temp) << endl;		//合法
```



在下面的一个例子中，Stonewt会被转换为int，然后用于数组下标的索引：

```cpp
Stonewt temp;
int array[5];
cout << array[temp] << endl;
```



在 C++98 中，关键字 explicit 不能用于转换函数，但 C++11 消除了这种限制。有了声明后，需要强制转换时将调用这些运算符：

```cpp
Stonewt temp;
int number = temp;			// 非法
int number = int(temp);		// 合法
```



## 转换函数和友元函数

假设定义了Stonewt的加法重载函数，double转换到Stonewt以及Stonewt转换到double的函数。

```cpp
//以下两个加法重载只能存在一个
Stonewt operator+(const Stonewt & st) const {}
friend Stonewt operator+(const Stonewt & st1,const Stonewt & st2) const {}

// double 转换到 Stonewt
Stonewt(double floating);

// Stonewt 转换到 double
operator double(void) const;
```



如果使用了类成员运算符重载（非友元函数的运算符重载） 和 仅double转换到Stonewt的转换，以下是允许的：

```cpp
Stonewt tempSt1,SumSt;
double tempD;
SumSt = tempSt1 + tempD;
```



它会被转换为（虽然需要提供Stonewt类型的参数，但是有double到Stonewt的自动类型转换）：

```cpp
SumSt = tempSt1.operator+(tempD);
```



但如果将tempSt1和tempD的位置互换，则不行：

```cpp
SumSt = tempD + tempSt1;			// 非法
SumSt = Stonewt(tempD) + tempSt1;	// 合法
```

因为编译器不会将tempSt1（double）类型转换为Stonewt，在调用tempSt1的成员运算符重载函数，当然可以使用强制类型转换，显示的将double转换为Stonewt则可以。

但如果使用友元函数，则支持上面的操作，因为友元函数是先判断是否存在可以调用的函数，判断时发现tempD(double)可以自动转换为Stonewt。



当**double 转换到 Stonewt** 和 **Stonewt 转换到 double**同时存在，则会出现下面的问题：

```cpp
Stonewt tempSt1,SumSt;
double tempD;
SumSt = tempSt1 + tempD;
```

在第三条语法中，具有二义性，即：

将tempSt1转换为double与tempD进行编译器内置的double + double的操作。

将tempD转换为Stonewt，进行用户重载的Stonewt + Stonewt的操作。

以上两种都是可以的，但两者同时存在，所以编译器不会允许编译通过。



一种解决方法是，将**Stonewt 转换到 double**声明为explicit 关键字，然后在使用的时候进行强制类型转换。



如果只有在赋值的时候，才会使用到将**Stonewt 转换到 double**，则可以重载`赋值(=)`运算符。



## 赋值构造和重载赋值运算符函数

不同之处：

- 赋值构造函数的用于，构造一个新的对象，然后将一个已存在的对象，赋值给这个新构造的对象。
- 重载赋值运算符用户，将一个已存在的对象，赋值给另一个已存在的对象。



相同之处：

- 两个函数都必须是成员函数，而不能是友元函数



### 赋值构造函数

赋值构造函数用于将一个对象复制到新创建的对象中。

按递参数传递，而不是常规的赋值过程中。类的复制构造函数原型通常如下

```
Class_name(const Class_name & [标识符]);
```



新建一个对象并将其初始化为同类现有对象时，复制构造函数都将被调用。

这在很多情况下都可能发生，最常见的情况是将新对象显式地初始化为现有的对象。

例如，假设 motto是一个 StringBad 对象，则下面4种声明都将调用复制构造函数：

- StringBad ditto(motto);
- StringBad metoo = motto;
- StringBad also = StringBad(motto);
- String Bad * pStringBad = new StringBad(motto);



### 重载赋值运算符

将一个已存在的对象，赋值给另一个已存在的对象。

```
class_name & operator=(const class_name& [标识符])
```







# 类继承

可使用名为“继承”的机制从现有类派生新类。 用于派生的类称为特定派生类的“基类”。 使用以下语法声明派生类：

```c++
class Derived : [virtual] [access-specifier] Base
{
   // member list
};
class Derived : [virtual] [access-specifier] Base1,
   [virtual] [access-specifier] Base2, . . .
{
   // member list
};
```

在类的标记（名称）后面，显示了一个后跟基本规范列表的冒号。

冒号后面是访问修饰符，它是关键字 **`public`**、**`protected`** 或 **`private`** 之一，默认为**`private`**。用于控制派生类对于基类的权限。

可指定多个基类，并用逗号分隔。 如果指定了单个基类，则继承模型为**单一继承**。 如果指定了多个基类，则继承模型称为**多重继承**。



派生类不能直接访问基类的私有成员，而必须使用基类的公有方法来访问私有的基类成员。





## 派生类构造函数

派生类不仅要对新的成员进行初始化，还需要对基类成员进行初始化。初始化派生类的成员必须手动进行，而初始化基类成员，可以调用基类的构造函数（或赋值构造函数）：

```cpp
class user {

public:

	user(const string& newName = "", const unsigned int& newAge = 0) {

		user& object = *this;

		object.Name = newName;
		object.Age = newAge;

	}
	user(const char* newName, const unsigned int& newAge = 0) : user((string)(newName), newAge) { ; }


	user(const user& source);




private:

	string Name;
	int Age;

public:

};

//1. 将基类 user 派生一个 group 类型
class group : public user{

public:
	
	group(const string& newGroupName = "", const string& newName = "", const unsigned int& newAge = 0)
		: group(newGroupName, user(newName, newAge)) { ; }


	group(const char* newGroupName, const string& newName = "", const unsigned int& newAge = 0)
		: group((string)(newGroupName), user(newName,newAge)) { ; }
	
	//2. 派生类 group 构造函数，支持一个 user 基类的引用变量，调用 user 基类的赋值构造函数进行初始化
	group(const string& newGroupName, const user& newUser) : user(newUser){

		group& object = *this;

		object.groupName = newGroupName;

	}

private:
	
	string groupName;
	

public:

};
```



## 基类和派生类的关系

基类的引用和指向基类的指针，可以去引用或指向一个派生类对象，例如：

```C++
group tmpGroup;

user * tmpbase = & tmpGroup;
user & base = tmpGroup;
```

但这只是单项的，派生类的指针或引用，不能指向或引用一个基类对象。



由此可见，可以将一个派生类对象赋值给一个基类的对象，例如：

将派生类group赋值给基类user;

在基类user没有定义赋值构造函数的时候，默认存在一个user(const user & [标识符]);的赋值构造函数。

const user& 是可以引用一个 group 对象的。



is-a(is-a-kind-of)：描述某种事物是另一种事物的一种类型或种类

has-a：某种事物拥有或包含另一种事物

is-like-a：如果A “is-like-a” B，那么可以理解为A像B，但并不完全是B。

is-implemented-as-a：如果A “is-implemented-as-a” B，那么可以理解为A是通过B来实现的

user-a：如果类A “uses-a” 类B，那么可以理解为类A使用了类B。



## 虚函数

假设现在存在一个base基类，然后通过base基类派生出一个Derived派生类，然后这两个内中都存在一个同名的方法（函数）。

如果是是通过对象来进行访问，那么base对象调用base类中的方法，Derived对象调用Derived类中的方法。

```C++
#include <iostream>
#include <string>

using std::cout;
using std::endl;
using std::string;


class Base {

public:
	Base(const string& newBaseName = "");

	Base(const char* newBaseName) : Base((string)(newBaseName));

private:
	string BaseName;

public:
	void setName(const string& newBaseName);
	string getName(void) const;
	
};


class Derived : public Base {

public:
	Derived(const string& newDerivedName = "",const string & newBaseName = "") 
		: Base(newBaseName);
		
	Derived(const char* newDerivedName, const string newBaseName = "") 
		: Derived((string)(newDerivedName), newBaseName);

private:
	string DerivedName;

public:
	void setName(const string& newDerivedName);
	string getName(void) const;

};

```

```c++
Base a = "BaseName";
cout << a.getName() << endl; // Base::getName()
Derived b = "DerivedName";
cout << b.getName() << endl; // Derived::getName()
```



如果一个函数只在派生类中存在，那么你不能通过基类的引用或指针来调用它。

```C++
#include <iostream>
#include <string>

using std::cout;
using std::endl;
using std::string;


class Base {

public:
	// 假设基类中没有 getName函数
	// string getName(void) const;
	
};


class Derived : public Base {、

public:
    // getName函数仅在派生类中存在
	string getName(void) const;

};

```

```C++
Base a = "BaseName";
Derived b = "DerivedName";

Derived & P_Derived = b;
cout << p_base.getName() << endl; // Base::getName() 

Base & p_Base = a;
cout << p_base.getName() << endl; // 非法语句，Base中没有getName函数，无法调用Derived类中的getName函数
```



如果一个基类的函数被声明为`virtual`，那么在所有从这个基类派生出来的类中，（与）这个函数（同名）都会自动成为虚函数。

对以上代码的修改，只需要将Base类中部分修改为：

```cpp
class Base {
...

public:
	virtual void setName(const string& newBaseName);
	virtual string getName(void) const;

...
}
```



如果一个函数在基类和派生类中存在，但**未被**声明为虚函数，则通过指针或引用的类型来确定调用哪一个函数。

```c++
Base a = "BaseName";
Derived b = "DerivedName";

Base & p_Base = a;
cout << p_base.getName() << endl; // Base::getName()

Base & P_Derived = b;
cout << p_base.getName() << endl; // Base::getName() , 即使它指向的是一个Derived对象
```



如果一个函数在基类和派生类中存在，但**且被**声明为虚函数，则调用引用或指针所指向的对象类型的函数版本

```cpp
Base a = "BaseName";
Derived b = "DerivedName";

Base & p_Base = a;
cout << p_base.getName() << endl; // Base::getName()

Base & P_Derived = b;
cout << p_base.getName() << endl; // Derived::getName() , 根据引用的对象来调用函数，而不是引用的类型
```



## 虚函数重定义

如果一个虚函数在基类和派生类中的函数特征（即函数参数列表）不同，那么可以说在派生类中对这个虚函数进行了重定义。

如果在派生类中对基类的虚函数进行了重定义，那么编译器会自动隐藏基类中的虚函数，此时只能调用派生类中的虚函数，无法调用基类中的虚函数。



假设创建了如下所示的代码：

```cpp
class Dwelling {
public:
    virtual void showperks(int a) const;
};

class Hovel : public Dwelling {
public:
    virtual void showperks() const;
};

```



```cpp
Hovel test;
test.showperks(1);	// 错误
test.showperks();	// 正确
```



如果重新定义继承的方法，应确保与原来的原型完全相同。

如果返回类型是基类引用或指针，则可以修改为指向派生类的引用或指针（这种例外是新出现的），称为返回类型协变（covariance of return type）。

注意下面代码中 build 虚函数的返回值：

```cpp
class Dwelling
{
public :
    
    virtual Dwelling &build(int n);
};

class Hovel: public Dwelling
{
public :
    
    virtual Hovel &build(int n); 
};

```



如果基类声明被重载了，则应在派生类中重新定义所有的基类版本。

如果只重新定义一个版本，则另外两个版本将被隐藏，派生类对象将无法使用它们。

```cpp
class Dwelling
{
public :
    // three overloaded showperks()
    virtual void showperks(int a) const;
    virtual void showperks(double x) const;
    virtual void showperks() const;
};

class Hovel: public Dwelling
{
public :
    // three redefined showperks()
    virtual void showperks(int a) const;
    virtual void showperks(double x) const;
    virtual void showperks() const;
};
```



注意，如果不需要修改，则新定义可只调用基类版本：

```cpp
void Hovel::showperks() const
{
    Dwelling::showperks();
}
```





## 访问控制protected

protected于private类似，private只能被当前类的成员函数所访问，而protected类型可以被当前类以及派生类的成员所访问。

对于类的外部，protected具有相同的特性。

对于类数据成员，最好采用私有访问控制，不要使用保护访问控制，同时通过基类方法使派生类能够访问基类数据。

对于类成员函数，保护访问控制很有用，它让派生类能够访问公众不能使用的内部函数。



## 纯虚函数

在C++中，**抽象基类**和**纯虚函数**是面向对象编程的重要概念。

**抽象基类**（Abstract Base Class，ABC）是一种只能用作基类的类，不能实例化。这种类的主要目的是为派生类提供一个公共的接口。抽象基类至少包含一个纯虚函数。

```cpp
class AbstractClass {
public:
    // 纯虚函数
    virtual void pureVirtualFunction() = 0;
};
```



**纯虚函数**（Pure Virtual Function）是在基类中声明的虚函数，它在基类中没有定义，但要求任何派生类必须定义。纯虚函数是通过在声明中赋值0来指定的。

```cpp
virtual void pureVirtualFunction() = 0;
```

可以选择在基类中为纯虚函数提供定义：

```cpp
class AbstractClass {
public:
    // 纯虚函数
    virtual void pureVirtualFunction() = 0;
};

void AbstractClass::pureVirtualFunction(){

	// ... 代码定义 ... 

}
    
```



如果一个类包含一个或多个纯虚函数，那么这个类就是抽象基类。派生类必须实现所有的纯虚函数，否则它也将成为抽象基类。

```cpp
class DerivedClass : public AbstractClass {
public:
    // 必须实现的纯虚函数
    void pureVirtualFunction() override {
        // 具体实现
    }
};
```



## 继承和动态内存分配

当基类和派生类都采用动态内存分配时，派生类的析构函数、复制构造函数、赋值运算符都必须使用相应的基类方法来处理基类元素。

对于析构函数，这是自动完成的。

```cpp
baseDMA::~baseDMA() // takes care of baseDMA stuff
{
    delete []label;
}

hasDMA::~hasDMA() // takes care of hasDMA stuff
{
    delete []style;
}

```

对于构造函数，这是通过在初始化成员列表中，调用基类的复制构造函数来完成的；如果不这样做，将自动调用基类的默认构造函数。

```cpp
baseDMA::baseDMA(const baseDMA &rs)
{
    label = new char[std::strlen(rs.label) + 1];
    std::strcpy(label, rs.label);
    rating = rs.rating;
}

hasDMA::hasDMA(const hasDMA &hs) : baseDMA(hs)
{
    style = new char[std::strlen(hs.style) + 1];
    std::strcpy(style, hs.style);
}

```

对于赋值运算符，这是通过使用作用域解析运算符显式地调用基类的赋值运算符来完成的。

```cpp
baseDMA & baseDMA::operator=(const baseDMA & rs)
{
    if (this == &rs)
        return *this;
    delete []label;
    label = new char[std::strlen(rs.label) + 1];
    std::strcpy(label, rs.label);
    rating = rs.rating;
    return *this;
}

hasDMA & hasDMA::operator=(const hasDMA &hs)
{
    if(this == &hs)
        return *this;
    baseDMA::operator=(hs); // copy base portion
    delete []style; // prepare for new style
    style = new char[std::strlen(hs.style) + 1];
    std::strcpy(style, hs.style);
    return *this;
}

```



## 派生类访问基类友元函数

派生类的友元函数可以直接访问派生类的私有成员，所以可以直接进行cout输出，但是无法直接访问基类的私有成员，只能通过访问基类的友元函数。

派生类如何使用基类的友元，因为友元不是成员函数，所以不能使用作用域解析运算符来指出要使用哪个函数，可以使用强制类型转换。

```cpp
//基类的友元函数
std::ostream &operator<<(std::ostream &os, const baseDMA & rs)
{
    os << "Label: " << rs.label << std::endl;
    os << "Rating: " << rs.rating << std::endl;
    return os;
}

```

```cpp
//派生类的友元函数
std::ostream & operator<<(std::ostream & os, const hasDMA &rs)
{
    os << (const baseDMA &)hs;
    // 上面的代码将会被转换为：
    // operator(os,(const baseDMA&)hs);
	// 也可以直接使用 这种方法 暂未验证
    
    os << "Style: " << hs.style << std::endl;
    return os;
}

```



## 各种继承方式

![image-20240317131128957](images/C&C++.assets/image-20240317131128957.png)



## 使用私有继承



### 1. 初始化基类组件

使用私有继承，在构造函数的初始化列表中，应该使用私有基类的类名来对基类进行构造。

```C++
class Student : private std::string{

public:

	Student(const & std::string Name) : std::string(Name);
	Student(const char * Name) : std::string(Name);

}
```



### 2. 访问基类的方法

私有继承使得能够使用类名和作用域解析运算符来调用基类的方法

```C++
class Student : private std::string {

public:
	
	size_t len(void){
	
		//调用string基类中的size方法
		//类似于 string a; a.size();
		return std::string::size();
	
	}	

}
```



### 3. 访问基类对象

由于 Student 类是从 string 类派生而来的，因此可以通过强制类型转换，将Student 对象转换为 string 对象;结果为继承而来的string对象。

指针 this 指向用来调用方法的对象，因此*this 为用来调用方法的对象，在这个例子中，为类型为 Student 的对象。

为避免调用构造函数创建新的对象，可使用强制类型转换来创建一个引用。

```C++
const string & Student::Name() const
{

	return (const string & ) *this;

}
```



### 4. 访问基类友元函数

可以通过显式地转换为基类来调用正确的函数：

```C++
ostream & operator<<(ostream & os,const Student & stu)
{
	os << "Scores for" << (const string &) stu << ":\n";
}
```

显式地将 stu 转换为 string对象引用，进而调用函数 operator<<(ostream &,const String &)。



引用 stu 不会自动转换为 string引用。根本原因在于,在私有继承中,在不进行显式类型转换的情况下,不能将指向派生类的引用或指针赋给基类引用或指针。

另一个原因是，由于这个类使用的是多重继承，编译器将无法确定应转换成哪个基类，如果两个基类都提供了函数 operator<<( )。



## 使用using重新定义访问权限

使用一个usimg声明(就像名称空间那样)，来指出派生类可以使用特定的基类成员，即使采用的是私有派生。

假如希望Student类直接使用string类中的size函数。

```cpp
class Student : private std::string {

public:

	using std::string::size;

}
```

注意，using声明只使用成员名——圆括号、函数特征标和返回类型。引入一个函数，会引入它的所有重载版本（如果有的话）。



# 多重继承

![，](images/C&C++.assets/image-20240324124338557.png)

假设首先从 Singer和 Waiter 公有派生出 SingingWaiter。

因为 Singer 和 Waiter 都继承了一个 Worker 组件，因此 SingingWaiter 将包含两个 Worker 组件。



例如，通常可以将派生类对象的地址赋给基类指针，但现在将出现二义性：

```cpp
SingingWaiter ed;
Worker *pw=&ed;
```



通常，这种赋值将把基类指针设置为派生对象中的基类对象的地址。

但ed中包含两个 Worker 对象有两个地址可供选择，所以应使用类型转换来指定对象：

![image-20240324124901108](images/C&C++.assets/image-20240324124901108.png)

```cpp
Worker *pwl=(Waiter *)&ed;
Worker *pw2=(Singer *)&ed;
```



### 1. 虚基类

虚基类使得从多个类(它们的基类相同)派生出的对象只继承一个基类对象。例如，通过在类声明中使用关键字 virtual，可以使 Worker 被用作 Singer 和 Waiter 的虚基类(virtual和 public 的次序无关紧要)：

```cpp
class Singer : virtual public Worker { ... };
class Waiter : public virtual Worker { ... };
```



然后，可以将 SingingWaiter 类定义为：

```cpp
class SingerWaiter : public singer , public waiter { ... }; 
```

现在，SingingWaiter 对象将只包含 Worker 对象的一个副本。从本质上说，继承的 Singer 和 Waiter 对象共享一个 Worker 对象，而不是各自引入自己的 Worker 对象副本。

![image-20240324125502012](images/C&C++.assets/image-20240324125502012.png)



### 2. 虚基类构造函数

使用虚基类时，需要对类构造函数采用一种新的方法。对于非虚基类，唯一可以出现在初始化列表中的构造函数是即时基类构造函数。但这些构造函数可能需要将信息传递给其基类。



1. C类的构造函数只能调用B类的构造函数，而B类的构造函数只能调用A类的构造函数。
2. 这里，C类的构造函数使用值 q，并将值m和n传递给B类的构造函数;
3. 而B类的构造函数使用值m，并将值n传递给 A 类的构造函数。



```cpp
class A {
    int a;
public:
    A(int n=0):a(n){}
};

class B:public A {
    int b;
public:
    B(int m=0, int n=0):A(n), b(m){}
};

class C:public B {
    int c;
public:
    C(int q=0, int m=0, int n=0):B(m, n), c(q){}
};
```





在C++中，如果一个类有虚基类，自动传递信息时，将通过2条不同的途径(Waiter和Singer)将wk传递给 Worker 对象。为避免这种冲突，C++在基类是虚的时，禁止信息通过中间类自动传递给基类。

```cpp
SingingWaiter(const Worker &wk, int p=0, int v=Singer::other)
: Waiter(wk, p), Singer(wk, v) {} // flawed
```



在构造函数中，必须显式地调用虚基类的构造函数。如果不这样做，编译器将使用虚基类的默认构造函数：

```cpp
SingingWaiter(const Worker &wk, int p=0, int v=Singer::other)
: Worker(wk), Waiter(wk, p), Singer(wk, v) {}

```



### 3. 成员函数

如果一个类从多个基类继承了同名的成员函数，那么在派生类中直接调用这个函数会产生二义性。

为了解决这个问题，可以使用作用域解析运算符来指定调用哪个基类的成员函数。例如，`newhire.Singer::Show();` 就是调用 `Singer` 类的 `Show()` 函数。



更好的做法是在派生类中重新定义这个函数，并在函数内部明确调用需要的基类函数：

```cpp
void SingingWaiter::Show() {
    Singer::Show();
    Waiter::Show();
}
```

`SingingWaiter` 类的 `Show()` 函数就会先调用 `Singer` 类的 `Show()` 函数，然后再调用 `Waiter` 类的 `Show()` 函数。

这样做可能会导致一些信息被重复显示，因为 `Singer::Show()` 和 `Waiter::Show()` 都可能会调用 `Worker::Show()`。



可以将 `Show()` 函数分解为多个部分，每个部分只显示一部分信息，然后在派生类中组合这些部分。

```cpp
void Worker::Data() const {
    cout << "Name: " << fullname << "\n";
    cout << "Employee ID: " << id << "\n";
}

void Waiter::Data() const {
    cout << "Panache rating: " << panache << "\n";
}

void Singer::Data() const {
    cout << "Vocal range: " << pv[voice] << "\n";
}

void SingingWaiter::Data() const {
    Singer::Data();
    Waiter::Data();
}

void SingingWaiter::Show() const {
    cout << "Category: singing waiter\n";
    Worker::Data();
    Data();
}
```



### 4. 如何理解虚基类

1. 基类本身无法决定是否成为虚基类，这是由派生类决定的。
2. 派生类可以使用`virtual`关键字来声明其基类，这表明该基类可以被多个派生类共享。
3. 如果一个派生类从多个基类继承，且这些基类中有两个或更多的相同的间接虚基类，那么这个虚基类将会被共享。



例子：

1. 有一个基类`A`
2. 三个派生类`B1`、`B2`和`B3`，它们都继承自`A`
3. `B1`和`B2`将`A`声明为虚基类，而`B3`则直接继承`A`。
4. 派生类`C`，它继承自`B1`、`B2`和`B3`。
5. `C`会有两个`A`基类的实例，其中一个`A`实例是由`B1`和`B2`共享的（因为它们将`A`声明为虚基类），另一个`A`实例则是由`B3`独享的（因为`B3`直接继承`A`）



### 5. 成员优先级

一个成员名如何优先于另一个成员名？派生类中的名称优先于直接或间接祖先类中的相同名称。

例1：

1. 基类A由omg函数
2. 派生类B继承基类A，派生类B定义了自己的omg函数
3. 派生类C继承派生类B，如果在派生类C中调用omg函数，则调用派生类B的omg函数，而不是基类A中的omg函数
4. 如果派生类C也定义了自己的omg函数，则直接调用自身的omg函数。



例2：

1. 基类A由omg函数
2. 派生类B1和B2分别继承基类A，派生类B1和B2分别定义了自己的omg函数
3. 派生类C继承派生类B1和B2，如果在派生类C中调用omg函数，则产生二义性。
4. 如果派生类C定义了自己的omg函数，则直接调用自身的omg函数。





# 模板类

## 1.模板类的定义

```
template <class Type>
template <typename Type>
```

- 关键字template表示要定义一个模板。
- class表明Type是一个通用的类型说明符，可以用typename替代。
- Type指的是泛行名，当模板被调用时将被具体的类型值取代。（如：int、string）



## 2. 模板类方法定义

```
void classname<Type>::Fun(Type & n);
```

如果在类声明中定义方法（内联定义），则可以省略模板前缀和类型限定符

```
void Fun(Type & n);
```



模板的具体实现——如用来处理int对象——被称之为实例化或具体化。

不能将模板成员函数放在独立的实现文件(.c)中，最简单的方法是将所有模板信息放在同一个头文件中。



## 3. 使用模板类

仅包含模板并不能生成模板类，必须请求实例化，也就是声明一个类型为模板类的对象。

```cpp
template <class T>
class Stack {
	//...
}

//...

Stack<int> x;
Stack<double> King;
```

以上将会生成两个独立的类声明和两组独立的方法

- 类声明`Stack<int>`将使用int类型替换模板中所有的Type
- 类声明`Stack<double>`将使用double类型替换模板中的所有double
- `Stack<Type>` 泛行标识符（这里为Type）称为“类型参数”，类似于变量，只能赋给类型。


注意：必须显式地提供所需的类型，这与常规的函数模板是不同的，因为编译器可以根据函数的参数类型来确定要生成哪种函数:



## 4. 非类型参数

`int n`指出n的类型为int，这种参数（指定特定的类型，而不是用泛型名）称之为**非类型**或**表达式**参数。

可以为类模板的泛型设置默认值。

不可以为函数模板的泛型设置默认值。

可以为类模板和函数模板的非类型参数设置默认值。

```cpp
template <class T = double,int n =10>
class Stack {
	
private:
	T array[n];
}

//...

Stack<int,20>;
Stack<>;
```



浮点模板是非标准的，下面的代码是非法的。

```cpp
template<double v>
class Double {

	T x;
};
```



Stack构造函数中的三条语句都是非法的。

不能修改参数的值。

不能使用参数的地址。

```cpp
template <int n>
class Stack {
	
private:
	Stack(void){
	
		//n = 10;
		//n++;
		//int *p = &n;
	
	}
}
```





非类型模板参数的主要缺点是，每种数组大小都将生成自己的模板。也就是说，下面的声明将生成两个独立的类声明：

```cpp
ArrayTP<double, 12> eggweights;
ArrayTP<double, 13> donuts;
```



但下面的声明只生成一个类声明，并将数组大小信息传递给类的构造函数：

```cpp
Stack<int> eggs(12);
Stack<int> dunkers(13);
```

这就是说，`ArrayTP<double, 12>`和`ArrayTP<double, 13>`是两个完全不同的类型，即使它们的元素类型（`double`）是相同的。因为在模板实例化时，非类型参数的每个不同值都会生成一个新的模板实例。



### 5. 模板的多功能性



#### 5.1 模板的递归

归使用模板：另一个模板多功能性的例子是，可以递归使用模板。

例如，对于前面的数组模板定义，可以这样使用它:

```cpp
ArrayTP< ArrayTP<int,5>,10> twodee;
```



这使得twodee 是一个包含 10个元素的数组,其中每个元素都是一个包含5个`int`元素的数组。与之等价的常规数组声明如下:

```cpp
int twodee[10][5];
```



请注意，在模板语法中，维的顺序与等价的二维数组相反。



#### 5.2 使用多个类型参数

```cpp
//pairs.cpp-- defining and using a Pair template
#include <iostream>
#include <string>
template<class T1, class T2>
class Pair {
private:
    
    T1 a;
    T2 b;
    
public:
    T1 & first(void) { return a; }
    T2 & second() { return b; }
};

int main(void){
    
    Pair<int,double> p1;
    
    p1.first() = 15;
    p2.second() = 15.5;
    
    return 0;
    
}
```



## 6. 具体化

### 6.1 隐式实例化

```
ArrayTP<int,100> stuff; 
```



编译器在需要对象之前，不会生成类的隐式实例化。

```
ArrayTP<double,30>* pt; //指针
```



第二条语句导致编译器生成类定义，并根据该定义创建一个对象。

```
pt = new ArrayTP<double,30>; // 现在需要一个对象。
```



### 6.2 显示实例化

当使用关键字 `template` 并指出所需类型来声明类时，编译器将生成类声明的显式实例化(explicit instantiation)。

声明必须位于模板定义所在的名称空间中。

例如，下面的声明将 `ArrayTP<string,100>` 声明为一个类：

```cpp
template class ArrayTP<string,100>; // 生成 ArrayTP<string,100> 类。
```



在这种情况下，虽然没有创建或提及类对象，编译器也将生成类声明(包括方法定义)。

隐式实例化一样，也将根据通用模板来生成具体化。



### 6.3 显示具体化

显式具体化(explicit specialization)是特定类型(用于替换模板中的泛型)的定义。

有时候，可能需要在为特殊类型实例化时，对模板进行修改，使其行为不同。



如果 `T` 表示一种类，则只要定义了 `T::operator>()` 方法，就可以为所有类型进行排序。

不过对于char*类型时，这要求类定义使用 `strcmp()`，而不是 `>` 来对值（地址）进行比较。



具体化类模板定义的格式如下：

```cpp
template <> class Classname<specialized-type-name> {...};
```



提供一个专供 `const char *` 类型使用的 `SortedArray` 模板，可以使用类似于下面的代码：

```cpp
template<> class SortedArray<const char *>
{
    // details omitted
}
```



当请求 `const char *` 类型的 `SortedArray` 模板时，编译器将使用上述专用的定义，而不是通用的模板定义：

```cpp
// 使用通用定义
SortedArray<int> scores;
// 使用专用定义
SortedArray<const char *> dates;
```





### 6.4 部分具体化

C++还允许部分具体化(partial specialization)，即部分限制模板的通用性。

例如，部分具体化可以给类型参数之一指定具体的类型：



通用模板

```cpp
template<class T1, class T2> class Pair {...};
```



T2 设置为 int 的特化

```cpp
template <class T1> class Pair<T1, int> {...};
```



关键字 `template` 后面的尖括号声明的是没有被具体化的类型参数。

因此，上述第二个声明将 `T2` 具体化为 `int`，但 `T1` 保持不变。

注意，如果指定所有的类型，则尖括号将为空，这将导致显式具体化：

```cpp
// T1 和 T2 都设置为 int 的特化
template <> class Pair<int, int> {...};
```



如果有多个模板可供选择，编译器将使用具体化程度最高的模板。给定上述三个模板，情况如下：

```cpp
Pair<double, double> p1; // 使用通用 Pair 模板
Pair<double, int> p2; // 使用 Pair<T1, int> 部分特化
Pair<int, int> p3; // 使用 Pair<int, int> 显式特化
```



通过为指针提供特殊版本来部分具体化现有的模板：

```cpp
template<class T>
// 通用版本
class Feeb {...};
template<class T*>
// 指针部分特化
class Feeb {...};
```



如果提供的类型不是指针，则编译器将使用通用版本；如果提供的是指针，则编译器将使用指针具体化版本：

```cpp
Feeb<char> fb1; // 使用通用 Feeb 模板，T 是 char
Feeb<char *> fb2; // 使用 Feeb<T*> 特化，T 是 char
```



如果没有进行部分具体化，则第二个声明将使用通用模板，将 `T` 转换为 `char *` 类型。如果进行了部分具体化，则第二个声明将使用具体化模板，将 `T` 转换为 `char`。部分具体化特性使得能够设置各种限制。例如，可以这样做：

```cpp
// 通用模板
template <class T1, class T2, class T3> class Trio {...};
// T3 设置为 T2 的特化
template <class T1, class T2> class Trio<T1, T2, T2> {...};
// T3 和 T2 都设置为 T1* 的特化
template <class T1> class Trio<T1, T1*, T1*> {...};
```



给定上述声明，编译器将作出如下选择：

```cpp
Trio<int, short, char *> t1; // 使用通用模板
Trio<int, short, short> t2; // 使用 Trio<T1, T2, T2> 特化
Trio<char, char *, char *> t3; // 使用 Trio<T1, T1*, T1*> 特化
```





