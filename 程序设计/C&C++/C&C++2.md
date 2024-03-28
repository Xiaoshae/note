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



