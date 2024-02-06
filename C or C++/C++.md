# 基础



## mian函数

```c++
int main(void){

	return 0;
}
```

1.  C/C++程序从main函数中开始执行
2. 第一行 int main( )叫函数头(function heading)，花括号({和})中包括的部分叫函数体
3. 每条完整的指令都称为语句，所有的语句都以分号结束，不能省略分号。
4. main()中最后一条语句叫做返回语句(returnstatement)，它结束该函数。



## 注释

注释以`//`打头，到行尾结束。注释可以位于单独的一行上，也可以和代码位于同一行。

符号`/*`和`*/`之间的部分，全部都是注释。

```C++
// 这里是一条注释

int main(void){
	return 0; // 后面这一部分也是注释。
}

/*
你好
这一部分全部都是注释
*/
```



## 命名空间

命名空间是一个声明性区域，为其内部的标识符（类型、函数和变量等的名称）提供一个范围。

命名空间范围内的所有标识符彼此可见，而没有任何限制。 **命名空间之外的标识符**可通过**使用每个标识符**的**完全限定名**来访问成员，也可通过**单个标识符的 using 声明**或命名空间中**所有标识符的 using 指令**来访问成员。 

使用namespace定义一个命名空间

```c++
namespace <标识符>{
	<C/C++源码>
	...
}
```



定义两个命名空间分别为`mathTools`和`englishTools`，在两个命名空间中都定义了两个函数，分别为`sum`和`reduce`。

```c++
int division()

namespace mathTools{
	int sum(......)
	
	int reduce(......)
}

namespace englishTools{
	int sum(......)
	
	int reduce(......)
        
    int multiplication()
}
```



### 完全限定名访问

```c++
mathTools::sum(); //使用mathTools命名空间中的sum函数
mathTools::reduce();
englishTools::sum();//使用englishTools命名空间中的sum函数
englishTools::reduce();
```

！！错误示范

```c++
//不加命名空间名称访问函数
//命名空间外部没有sum()函数
sum();
//正确
mathTools::sum();

//在mathTools访问multiplication函数
//multiplication函数不在mathTools中，而是在englishTools中
mathTools::multiplication();
//正确
englishTools::multiplication();

//在mathTools命名空间中访问division函数
//division函数不在命名空间中，可以直接访问
mathTools::division();
//正确
division();
```



## using访问单个标识符

```c++
using mathTools::sum;//仅引入mathTools命名空间中的sum函数
sum();//此时可以直接使用sum函数

reduce();//错误，reduce还是不能直接访问
mathTools::reduce(); //reduce函数现在还需要完全限定名称

using mathTools::reduce();//再把reduce函数引入
reduce(); //此时就可以直接访问reduce函数了
```



### using 引入命名空间中的所有内容

```C++
using namespace mathTools; //引入mathTools命名空间中的所有内容
sum();
reduce();//正确，此时可以直接访问mathTools中所有内容
```

！！注意：

- 如果仅使用一个或两个标识符，则考虑 using 声明，以仅将单个标识符引入范围。
- using 指令可以放置在 .cpp 文件的顶部（在文件范围内），或放置在类或函数定义内。
- 避免将 using 指令放置在头文件 (*.h) 中，因为任何包含该标头的文件都会将命名空间中的所有内容引入范围，这将导致非常难以调试的名称隐藏和名称冲突问题。
- 在头文件中，始终使用完全限定名。 如果这些名称太长，可以使用命名空间别名将其缩短。

！！错误：

- 如果本地变量的名称与命名空间变量的名称相同，则隐藏命名空间变量。
- 使命名空间变量具有与全局变量相同的名称是错误的。



## 全局命名空间

如果一个内容（如：函数）没有在命名空间中定义，那么这个内容属于全局命名空间。

未在显式命名空间中声明某个标识符，则该标识符属于隐式全局命名空间的一部分。

尽量不要再全局命名空间中定义内容（main函数除外），若要显式限定全局标识符，请使用没有名称的范围解析运算符，有助于使其他人更轻松地了解你的代码。

```c++
//test.cpp file
#include <iostream>
using namespace std;

//sum函数定义在全局命名空间中，隐式在全局命名空间定义内容，不要使用这种方式
int sum(){
    ...
}

int ::division(){//显示的在全局命名空间中定义内容，如果不得已需要在全局命名空间中定义，请使用这种方法。
    ...
}

namespace Tools{
    //reduce函数定义在Tools命名空间中，而非全局命名空间
    int reduce(){
        ...
    }
}

int main(void){
	cout << "Welcome to my docs." << endl;
	return 0;
}
```



## 嵌套命名空间

C++命名空间可以嵌套，子命名空间可以直接访问父命名空间中的成员，而无需任何限定符，父命名空间需要访问子命名空间中的成员，就必须使用限定符。

```c++
namespace father{
	int number;
	
	int sum(){...}
	
	namespace child{
	
		int book;
		
		int rudece(){
			return number;//可以直接访问父命名空间中的内容
		}
	
	}
	
	int multiplication(){
		return child::book;//父命名空间访问子命名空间中的内容，必须使用限定符。
	}
	
}
```

命名空间是可以多次嵌套的，也可以拥有多个子命名空间，没有限制。

```c++
namespace one{
	
	namespace two{
		
		namespace three{
			...
		}
	
	}
    
    namespace childNamespace{
        ...
    }
}
```



## 内联命名空间

与普通嵌套命名空间不同，内联命名空间的成员会被视为父命名空间的成员。这意味着，如果你在父命名空间或内联命名空间中查找一个重载的函数，那么这两个命名空间中的所有重载版本都将被考虑在内。

```c++
namspace father {

	void func(int){...}

	inline namespace child{
		
		void func(double){...}
		
		void func(char){...}
	}

}

father::func(1);//调用father::func(int)
father::func(1.0);//调用father::child::func(double)
father::func('c');//调用father::child::func(char)

father::child::func(1); //!!注意:我这里使用的是整数
//此时只会搜索father::child命名空间中的，而不会搜索father命名空间中的
//调用father::child::func();
```



内联也是可以多次嵌套的，不推荐使用，只是了解这种方法从语法上来说是正确的

```C++
namspace father {

	void func(int){...}

	inline namespace child{
		
		void func(double){...}
		
		inline namespace Inline{
		
			void func(char){...}
		
		}
	}

}
father::func(1);//调用father::func(int)
father::func(1.0);//调用father::child::func(double)
father::func('c');//调用father::child::Inline::func(char)  !!注意:这里和上面的不同
```



如果你在一个内联命名空间中声明了一个模板，你可以在该内联命名空间的父命名空间中为这个模板声明一个专门化版本。

我们在内联命名空间`Inline`中声明了一个模板函数`func`，然后在`Inline`的父命名空间`Parent`中为这个模板函数声明了一个专门化版本。

当我们调用`Parent::func`并传入一个整数时，编译器会选择使用我们在`Parent`中声明的专门化版本。

```c++
namespace Parent {
    inline namespace Inline {
        template <typename T>
        void func(T) {
            cout << "General template\n";
        }
    }

    // 在父命名空间中为内联命名空间中的模板声明一个专门化版本
    template <>
    void func<int>(int) {
        cout << "Specialization for int\n";
    }
}

int main() {
    Parent::func(10);  // 输出 "Specialization for int"
    Parent::func(10.0);  // 输出 "General template"
}
```



如果将其反过来，在父命名空间中中声明模板，在内联命名空间中声明专门化的模板，则会出现错误。

在C++中，模板的专门化必须在模板首次声明的相同命名空间中进行。在你的代码中，你试图在内联命名空间`Inline`中专门化一个在父命名空间`Parent`中声明的模板，这是不允许的。

这里目前还不是很懂，如果在内联空间中声明模板，然后在父空间进行专门化，那么是此时认为父空间和内联空间是同一个空间，是允许的。而如果在父空间声明模板，在内联空间中进行专门化，此时认为父空间和内联命名空间不是同一个空间，是不允许的。

```c++
//！！错误代码！！
namespace Parent {
    template <typename T>
    void func(T) {
        std::cout << "General template\n";
    }

    inline namespace Inline {
        template <>
        void func<int>(int) {
            std::cout << "Specialization for int\n";
        }
    }
}

int main() {
    Parent::func(10);  // 输出 "Specialization for int"
    Parent::func(10.0);  // 输出 "General template"
}
```



首先，你可以创建一个父命名空间，并将接口的每个版本封装到嵌套在父命名空间内的其自己的命名空间中。

将最新或首选的版本的命名空间限定为内联。这个的命名空间中的所有成员都会被视为父命名空间的直接成员。

如果选择使用较旧版本，它仍然可以通过使用完全限定路径来访问它。

```c++
#include <iostream>

using std::cout;
using std::endl;

namespace Tools {

    namespace version1 {
        
        void func(void) {
            cout << "version1" << endl;
        }
    }

    namespace version2 {
        
        void func(void) {
            cout << "version2" << endl;
        }

    }

    //将最新版本存在的命名空间，声明为内联
    inline namespace version3 {
        
        void func(void) {
            cout << "version3" << endl;
        }

    }
}

int main() {

    //默认使用最新版本
    Tools::func(); 

    //也可以使用指定的版本
    Tools::version1::func();
    Tools::version2::func();
    Tools::version3::func();
}


//输出结果
/*
version3
version1
version2
version3
*/
```



当你在一个编译单元中首次声明一个命名空间，并且将它声明为内联命名空间时，该命名空间在该编译单元的所有后续声明中都将被视为内联的。

一个编译单元通常是指一个源文件（如`.cpp`文件），以及它直接或间接包含的所有头文件（如`.h`或`.hpp`文件）。

假设有`1.h`  `1.cpp`  `2.cpp`，其中`1.cpp` 和 `2.cpp` 都引用了 `1.h` ，`1.cpp` 和 `2.cpp` 也是两个不同的编译单元。

```c++
namespace father {

	//在第一次，将命名空间声明为内联，整个child命名空间全部都是内联
	inline namespace child {

		void func1(void) {
			cout << "func1" << endl;
		}
	}

	//即使这里没有inline，这一部分中的内容也是内联
	//如果第一次不使用inline，这里使用inline，则会报错，不能将非内联命名空间重新打开为内联
	namespace child {

		void func2(void) {

			cout << "func2" << endl;

		}

	}

}
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



