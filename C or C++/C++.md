















## 运算符重载

相同的符号进行多种操作叫做运算符重载(operator overloading)。

例如，除法运算符 `/` 表示了三种不同的运算：`int` 除法、`float` 除法和 `double` 除法。C++ 根据操作数的类型（上下文）来确定运算符的含义。

C++有一些内置的重载示例。C++还允许扩展运算符重载。









# 数组

数组是一种数据结构，可以存储多个同类型的值。每个值都存储在一个独立的数组元素中，计算机在内存中依次存储数组的各个元素。

数组的声明需要指出元素的类型、数组名和数组中的元素数。

例如，`int ragnar[7];`声明了一个名为`ragnar`的数组，该数组有7个元素，每个元素都可以存储一个`int`类型的值。

![image-20240207170028387](images/C++/image-20240207170028387.png)





数组被称为复合类型，因为它是使用其他类型创建的。

数组必须是特定类型的，例如`char`数组或`long`数组。

数组的类型是由其元素的类型决定的，例如`float loans[20];`声明的`loans`的类型是“float数组”。



数组元素通过索引进行访问，C++数组的索引从0开始。

例如，`months[0]`是`months`数组的第一个元素，`months[11]`是最后一个元素。



编译器不会检查使用的下标是否有效，如果赋值给不存在的元素，可能会引发问题，如破坏数据或代码，或导致程序异常终止。



## 数组初始化

只有在定义数组时才能使用初始化，此后就不能使用了，也不能将一个数组赋给另一个数组，但可以使用下标分别给数组中的元素赋值。

```C++
int cards[4] = {3，6，8，10};// okay
int hand[4];// okay
hand[4] = {5，6，7，9};// not allowed
hand = cards;// not allowed
```



初始化数组时，提供的值可以少于数组的元素数目。

如果只对数组的一部分进行初始化，则编译器将把其他元素设置为0。

```C++
float hotelTips[5] = {5.0,2.5};
```



只要显式地将第一个元素初始化为0，编译器会将其他元素都初始化为0。

```C++
long totals[500]={0};
```



如果初始化为{1}而不是{0}，则第一个元素被设置为1，其他元素都被设置为0。

```C++
long totals[500]={1};
```



如果初始化数组时方括号内(`[]`)为空，C++编译器将计算元素个数。

例如，对于下面的声明，编译器将使`things` 数组包含4个元素：

```C++
short things[]=(1，5，3，8);
```



通常，让编译器计算元素个数是种很糟的做法，因为其计数可能与您想象的不一样。

例如，您可能不小心在列表中遗漏了一个值。



这种方法对于将字符数组初始化为一个字符串来说比较安全。

如果主要关心的问题是程序，而不是自己是否知道数组的大小，则可以这样做：

```c++
short things[]=(1，5，3，8); 
int num_elements=sizeof things/sizeof(short);
```



### 列表初始化数组

首先，初始化数组时，可省略等号(=):

```C++
double earnings[4]{1.2e4,1.6e4,1.1e4,1.7e4};
```



其次，可不在大括号内包含任何东西，这将把所有元素都设置为零

```c++
unsigned int counts[10]={};//all elements set to 0
float balances[100]{};//all elements set to 0
```



第三，列表初始化禁止缩窄转换

```c++
long plifs[]={25,92,3.0};			//not allowed
char slifs[4]{'h','i',1122011,\0'};	//not allowed
char tlifs[4]{'h','i',112,0'};		//allowed
```

1. 因为将浮点数转换为整型是缩窄操作，即使浮点数的小数点后面为零。
2. 因为1122011超出了char变量的取值范围(这里假设char 变量的长度为8位)。
3. 语句可通过编译，因为虽然112是一个int值，但它在char 变量的取值范围内。



# C风格字符串

在C++中，有两种处理字符串的方式：一种是C风格字符串，另一种是基于string类库的方法，这里主要介绍C风格的字符串。

C风格字符串是存储在内存的连续字节中的一系列字符，可以将字符串存储在char数组中。

C风格字符串的特殊性质是以空字符(null character)结尾，空字符被写作`\0`，其ASCII码为0，用来标记字符串的结尾。

```c++
char dog[6] = {'H', 'e', 'l', 'l', 'o', '\0'};	//not a string!
char cat[5] = {'H', 'e', 'l', 'l', 'o'};		// a string!
```



初始化字符串数组时，可以使用一个用引号括起的字符串，这种字符串被称为字符串常量或字符串字面值。

用引号括起的字符串隐式地包括结尾的空字符，因此不用显式地包括它。

```c++
char bird[11] = "Mr. Cheeps";
char fish[] = "Bubbles";
```



应确保数组足够大，能够存储字符串中所有字符——包括空字符。

处理字符串的函数根据空字符的位置，而不是数组长度来进行处理。



符串常量(使用双引号)不能与字符常量(使用单引号)互换。

字符常量(如’S’)是字符串编码的简写表示。在ASCII系统上，'S’只是83的另一种写法。

"S"不是字符常量，它表示的是两个字符(字符S和0)组成的字符串。



"S"实际上表示的是字符串所在的内存地址，因此不能将一个内存地址赋给字符变量。由于地址在C++中是一种独立的类型，因此C++编译器不允许这种不合理的做法。这是因为在C++中，字符串常量实际上是指向其第一个字符的指针，这将在后面的指针部分进行讨论。



### 字符串常量拼接

如果字符串很长，无法放到一行中，可以使用字符串常量的拼接（C/C++中都允许这种方法）。

将两个用引号括起的字符串合并为一个，任何两个由空白（空格、制表符和换行符）分隔的字符串常量都将自动拼接成一个。

以下三个字符串是等价的：

```C++
cout << "I'd give my right arm to be" " a great violinist.\n";
cout << "I'd give my right arm to be a great violinist.\n";
cout << "I'd give my right ar" "m to be a great violinist.\n";
```



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



# 结构体

![image-20240207200006741](images/C++/image-20240207200006741.png)

**声明结构体**：关键字 struct表明，这些代码定义的是一个结构的布局。

标识符 imnflatable 是这种数据格式的名称，因此新类型的名称为 inflatable。

大括号中包含的是结构存储的数据类型的列表，其中每个列表项都是一条声明语句。

```cpp
struct inflatable
{
    char name[20];
    float volume;
    double price;
};
```



**定义结构体变量**：定义结构后，便可以创建这种类型的变量了：

C++允许在声明结构变量时省略关键字struct（C语言不允许）：

```cpp
struct inflatable goose;  // 这是正确的
inflatable vincent;       // 这也是正确的
inflatable hat;
inflatable woopie_cushion;
inflatable mainframe;
```



**函数内部声明结构体**：如果你在`main`函数内部声明一个结构体，那么这个结构体只能在`main`函数内部被使用。

```cpp
int main() {
    struct inflatable {
        char name[20];
        float volume;
        double price;
    };
    inflatable hat;
    // ...
}
```

**函数外部声明结构体**：如果你在`main`函数外部声明一个结构体，那么这个结构体可以被程序中的任何函数使用。

```cpp
struct inflatable {
    char name[20];
    float volume;
    double price;
};

int main() {
    inflatable hat;
    // ...
}
```

**需前向声明的结构体**：如果你在`main`函数后面定义了一个结构体，那么你需要使用这个结构体之前进行前向声明。

```cpp
// 前向声明
struct inflatable;

int main() {
    // 使用结构体
    inflatable vincent;
    // ...
}

// 结构体定义
struct inflatable {
    char name[20];
    float volume;
    double price;
};
```





## 访问结构体

由于 hat 的类型为 infatable，因此可以使用成员运算符()来访问各个成员。

例如，hat.volume 指的是结构的 volume 成员，hat.price 指的是price 成员。

由于 price 成员被声明为 double类型，因此 hat.price 和 vincent.price 相当于是 double 类型的变量，可以像使用常规 double 变量那样来使用它们。

hat 是一个结构,而 hat.price 是一个 double 变量。

访问类成员函数(如 cin.getline( ))的方式是从访问结构成员变量(如vincent.price)的方式衍生而来的。





## 初始化

你可以使用花括号`{}`和逗号`,`来初始化结构体的成员。

```cpp
// 结构体定义
struct inflatable {
    char name[20];
    float volume;
    double price;
};
inflatable guest = {"Glorious Gloria", 1.88, 29.99};
```

在这个例子中，`"Glorious Gloria"`是`name`成员的值，`1.88`是`volume`成员的值，`29.99`是`price`成员的值。



**列表初始化结构体**：C++11支持使用列表初始化结构体，等号（`=`）是可选的。例如，你可以这样初始化一个`inflatable`类型的变量：

```cpp
inflatable duck{"Daphne", 0.12, 9.98};  // 在C++11中，可以省略等号
```



**初始化为零**：如果你在初始化结构体时没有提供任何值（即大括号内未包含任何东西），那么结构体的所有成员都将被设置为零。例如：

```cpp
inflatable mayor;  // mayor.volume 和 mayor.price 被设置为零，mayor.name 的每个字节都被设置为零
```



## 赋值

C++允许使用赋值运算符（`=`）将一个结构体赋值给另一个同类型的结构体。这种赋值方式会将一个结构体中的每个成员都设置为另一个结构体中相应成员的值，这被称为成员赋值（memberwise assignment）。



## 声明结构体时创建变量

可以在定义结构体的同时创建结构体变量。只需在结构体定义的结束括号后面添加变量名即可。

也可有在定义结构体的同时创建结构体变量的同时进行初始化。

```cpp
struct perks {
    int key_number;
    char car[12];
} mr_smith, ms_jones;  // 定义了两个perks类型的变量

struct perks {
    int key_number;
    char car[12];
} mr_glitz = {1, "Packard"};  // 初始化mr_glitz变量
```



## 无名结构体

可以声明没有名称的结构体类型，只需在定义结构体时省略名称。

这将创建一个这种类型的变量，但这种类型没有名称，因此以后无法创建这种类型的变量。

```cpp
struct {
    int x;
    int y;
} position;  // 创建了一个无名结构体变量position
```



C++结构体具有C结构体的所有特性，但还有更多。例如，C++结构体除了成员变量之外，还可以有成员函数。但这些高级特性通常被用于类中，而不是结构体中。



## 结构体数组

可以创建一个包含结构体的数组，就像创建基本类型数组一样。

例如，你可以创建一个包含100个`inflatable`结构体的数组：

```cpp
inflatable gifts[100];  // 创建一个包含100个inflatable结构体的数组
```



**初始化结构体数组**：你可以使用花括号（`{}`）和逗号（`,`）来初始化结构体数组。

每个元素的值都由逗号分隔，整个列表由花括号包围。

每个元素的值本身又是一个被花括号包围、用逗号分隔的值列表，这个列表用于初始化结构体的成员。例如：

```cpp
inflatable guests[2] = {
    {"Bambi", 0.5, 21.99},  // 初始化第一个结构体
    {"Godzilla", 2000, 565.99}  // 初始化第二个结构体
};
```



## 位字段

**定义位字段**：在C++中，你可以为结构体成员指定特定的位数，这在创建与硬件设备上的寄存器对应的数据结构时非常有用。

位字段的类型应为整型或枚举类型，后面跟着一个冒号和一个数字，数字指定了使用的位数。

```cpp
struct torgle_register {
    unsigned int SN : 4;  // 4位用于SN值
    unsigned int : 4;     // 4位未使用
    bool goodIn : 1;      // 有效输入（1位）
    bool goodTorgle : 1;  // 成功的torgling（1位）
};

//下面也是允许的
struct Inline {

	unsigned int SN : 4;
	bool DE : 1;
	unsigned int BT : 4;

};
```



**初始化和访问位字段**：你可以像通常那样初始化位字段，也可以使用标准的结构表示法来访问位字段。例如：

```cpp
torgle_register tr = {14, true, false};  // 初始化位字段
if (tr.goodIn) {                         // 访问位字段
    // ...
}
```



位字段通常用在低级编程中。一般来说，你可以使用整型和按位运算符来代替位字段。



# 共用体

**共用体的定义**：共用体是一种特殊的数据结构，它可以存储不同的数据类型，但只能同时存储其中的一种类型。

共用体的大小等于其最大成员的大小，因为它需要有足够的空间来存储最大的成员。

例如，你可以创建一个共用体，它可以存储`int`、`long`或`double`，但这三种类型不能同时存储。

```cpp
union one4all {
    int int_val;
    long long_val;
    double double_val;
};
```



可以使用共用体来存储不同类型的值，但需要注意的是，当你存储一个新的值时，之前的值会被覆盖。

```cpp
one4all pail;
pail.int_val = 15;  // 存储一个int
cout << pail.int_val;
pail.double_val = 1.38;  // 存储一个double，int_val的值会丢失
cout << pail.double_val;
```



**匿名共用体**：匿名共用体没有名称，它的成员将成为位于相同地址处的变量。

每次只有一个成员是活动的，程序员负责确定当前哪个成员是活动的。

```cpp
struct widget {
    char brand[20];
    int type;
    union {  // 匿名共用体
        long id_num;
        char id_char[20];
    };
};

widget Inu;
Inu.id_num 10;
Inu.id_char[0] = 'a'; //会覆盖其他共用体（id_num）的值


//也可以在函数中使用
int main(void){
	
	//定义匿名共用体
	union {
		int test;
		double aaa;
	};

	test = 100;
	cout << test << endl;
	aaa = 200;//会覆盖其他共用体（test）的值
	cout << aaa << endl;

}
```



# 枚举

**枚举类型的定义**：`enum`提供了一种创建符号常量的方式，可以代替`const`。它允许定义新类型，但必须按严格的限制进行。

`enum`的语法与结构类似。

```cpp
enum spectrum {red, orange, yellow, green, blue, violet, indigo, ultraviolet};
```

- 将 red、orange、yellow等作为符号常量,它们对应整数值 0~7。这些常量叫作枚举量(enumerator)
- 让 spectrum 成为新类型的名称;
- spectrum 被称为枚举(enumeration)。



可以用枚举名来声明这种类型的变量:

```cpp
spectrum band; //band a variable of type spectrum
```



## 赋值

只能将定义枚举时使用的枚举量赋给这种枚举的变量（在不进行强制类型转换的情况下）：

```cpp
band = blue;	//合法
band = 200;		//非法
```



枚举量是整型，可被提升为 int类型，但 int类型不能自动转换为枚举类型

因为orange + red在计算时将枚举提升为int类型，而int类型不能自动转换为枚举（不能赋值给枚举）：

如果将int类型强制转换为枚举类型，在赋值给枚举类型，则是合法的。

所以下面的操作是非法的：

```cpp
band = orange + red;					//非法
band = spectrum(orange + red;)			//合法
```



可以将枚举的计算结果赋值给int类型：

```
int color = orange + red;
```



每个枚举都有取值范围(range)，通过强制类型转换，可以将取值范围中的任何整数值赋给枚举变量，即使这个值不是枚举值。

```cpp
enum bitsone =l,two=2,four=4，eight=8);
bits myflag;

//下面的代码将是合法的
//其中6不是枚举值，但它位于枚举定义的取值范围内。
myflag = bits(6);
```



## 取值范围

1. **上限**：比枚举的最大值大的最小的2的幂，将它减去1，得到的便是取值范围的上限。

​	例如，如果枚举量的最大值是101，那么比这个数大的最小的2的幂是128，因此取值范围的上限为127。

2. **下限**：枚举量的最小值，如果它不小于0，则取值范围的下限为0。否则，采用与寻找上限方式相同的方式，但加上负号。

​	例如，如果最小的枚举量为-6，而比它小的最大的2的幂是-8（加上负号），因此下限为-7。



`Example`的取值范围是从-7到127。

比-6小最大的2的幂（加上负号）是-8，加上-(-1)为-7，所以范围最小值为-7

比101大的最小的2的幂是128，减去1为127，所以范围最小值为127.

```cpp
enum Example {
    Min = -6,  // 下限
    Max = 101  // 上限
};
```





## 设置枚举量的值

1. 赋值运算符来显式地设置枚举量的值。
2. 指定的值必须是整数。
3. 也可以只显式地定义其中一些枚举量的值。
4. 可以创建多个值相同的枚举量。

```cpp
enum bits {one=l,two=2,four=4,eight=8};			//来显式地设置枚举量的值

enum bigstep {first,second=100,third};			//显式地定义其中一些枚举量的值
//first在默认情况下为 0。
//后面没有被初始化的枚举量的值将比其前面的枚举量大1。因此，third的值为101。

enum bibg {zero,null=0,one,numerouno=1);		//创建多个值相同的枚举量
//zero和null都为0，one和umero_uno都为1。
```





# 指针

指针声明必须指定指针指向的数据的类型。

char 的地址与double 的地址看上去没什么两样，但 char 和 double 使用的字节数是不同的，它们存储值时使用的内部格式也不同。

```
int *p_updates;
```

p_updates 指向 int 类型，`p_updates`是指针(地址)，而`*pupdates`是int。



- `int *ptr;`：C风格，强调`*ptr`是`int`类型的指针。
- `int* ptr;`：C++风格，强调`int*`是指向`int`的指针类型。
- `int*ptr;`：也是合法的，但不常用。
- `int* p1, p2;`：`p1`是`int`类型指针，`p2`是普通`int`变量。



可以用同样的句法来声明指向其他类型的指针：

```
double *tax_ptr; 	//tax_ptr是一个指向double类型的指针。
char *str;			//str是一个指向char类型的指针。
```



**地址长度和作用**：虽然 tax ptr 和 str 指向两种长度不同的数据类型，但这两个变量本身的长度通常是相同的。

因为char 的地址与 double的地址的长度相同，这就好比 1016可能是超市的街道地址，而 1024 可以是小村庄的街道地址一样。

地址的长度或值既不能指示关于变量的长度或类型的任何信息，也不能指示该地址上有什么建筑物。



**指针类型的作用**：

针必须声明所指向的类型，因为地址本身只提供了内存的起始位置，没有提供类型或长度信息。

例如，`int* pt`和`double* pd`的长度相同，都是地址。

但由于声明了指针的类型，程序知道`*pd`是8字节的`double`值，`*pt`是4字节的`int`值。当打印`*pd`的值时，需要读取多少字节以及如何解释它们。







## 危险的指针

创建指针时，系统只分配存储地址的内存，不分配存储数据的内存。例如：

```cpp
long *fellow;
fellow = 223323;  // 错误！fellow未初始化，它的值是未知的
```



这里，`fellow`是一个指针，但我们并没有给它一个有效的地址，而是试图在一个未知的、可能无效的地址上存储值`223323`。这可能导致严重的错误，包括覆盖程序代码或其他重要数据。

**警告**：在使用指针之前，一定要将其初始化为一个确定的、适当的地址。



## 运算

指针和整数是不同的类型。

整数是数字，可以进行加减乘除等运算。

指针是地址，描述位置，**不能进行乘除法等运算**。



## 赋值

不能直接将整数赋给指针，需要强制类型转换：

```
int *pt;
pt = 0xB8000000;		//非法
pt = (int*)0xB8000000;	//合法
```



## 分配空间

在C语言中，可以使用malloc函数分配内存空间。



在C++中，可以使用`new`运算符在运行时为数据对象（包括基本类型和结构）分配未命名的内存。例如：

```cpp
int *pn = new int;  // 为int类型分配内存，并将地址赋给pn
```

为一个数据对象(可以是结构，也可以是基本类型)获得并指定分配内存的通用格式如下:

```cpp
typeName *pointer name =n ew typeName;
```



`new`可能无法分配内存，通常会引发异常或返回0（空指针）。空指针不会指向有效数据，常用来表示失败。



## 释放内存

`delete`用于释放`new`分配的内存空间



1. 当不再需要某块内存时，可以使用 `delete` 来释放这块内存。

2. 对空指针使用 delete 是安全的。

3. `delete` 只会释放指针所指向的内存，而不会删除指针本身，指针可以指向其他的内存空间。

4. 不要尝试释放已经释放的内存块，C++标准指出，这样做的结果将是不确定的。

5. 它用于 new分配的内存。这并不意味着要使用用于 new的指针，而是用于new的地址。

    ```cpp
    int *ps = new int; // 分配内存
    int *pq = ps; // 将第二个指针指向同一块内存
    delete pq; // 使用第二个指针删除
    ```



## 使用new创建动态数组

在C++中，创建动态数组很容易，只要将数组的元素类型和元素数目告诉`new`即可。例如，要创建一个包含10个`int`元素的数组，可以这样做：

```cpp
int *psome = new int[10]; // 获取10个int的内存块
```



`new`运算符返回第一个元素的地址。在这个例子中，该地址被赋给指针`psome`。当程序使用完`new`分配的内存块时，应使用`delete`释放它们。然而，对于使用`new`创建的数组，应使用另一种格式的`delete`来释放：

```cpp
delete [] psome; // 释放动态数组
```



方括号告诉程序，应释放整个数组，而不仅仅是指针指向的元素。如果使用`new`时不带方括号，则使用`delete`时也不应带方括号。如果使用`new`时带方括号，则使用`delete`时也应带方括号。



## 访问数组和指针的两种方式

### 下标法

这是最常见的方式，我们可以通过数组名和索引来访问数组中的元素。例如，如果我们有一个数组`arr`，我们可以通过`arr[i]`来访问第`i+1`个元素。

```cpp
int arr[5] = {1, 2, 3, 4, 5};
std::cout << arr[0]; // 输出第一个元素，结果为1
```



### 偏移法

在C++中，数组名实际上是指向数组第一个元素的指针。因此，我们可以通过指针来访问数组中的元素。例如，如果我们有一个指针`p`指向数组`arr`，我们可以通过`*(p+i)`或者`p[i]`来访问第`i+1`个元素。

由于取值运算符`*`的优先级高于算数运算符，所以必须要使用括号。

p+1，其中p是指针，指向数组的首地址，1表示的是数组中的第1个元素。

假设int类型占4字节，p指向的地址为0x8000，那么p+1的结果为0x8004，p+2的结果为0x8008。

假设double类型占8字节，p指向的地址为0x8000，那么p+1的结果为0x8008，p+2的结果为0x8016。

```cpp
int arr[5] = {1, 2, 3, 4, 5};
int* p = arr;
std::cout << *p;     // 输出第一个元素，结果为1
std::cout << *(p+1); // 输出第二个元素，结果为2
std::cout << p[2];   // 输出第三个元素，结果为3
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



# 循环



## for循环

`for`循环是一种常见的循环结构，它的基本语法如下：

```cpp
for (初始化; 条件; 增量) {
    // 循环体
}
```

- **初始化**：在循环开始前定义（可选）并设置循环控制变量的初始值，这个变量只在循环期间存在，一旦程序离开循环，该变量就会消失。
- **条件**：每次循环开始时检查的条件。如果条件为真（非零），则执行循环体；否则，循环结束。
- **增量**：在每次循环结束时更新循环控制变量的操作。
- **循环体**：当条件为真时执行的代码块。



例如，下面的代码将打印数字1到10（程序结束后i变量被释放）：

```cpp
for (int i = 1; i <= 10; i++) {
    std::cout << i << std::endl;
}
```



### 范围for循环

范围for循环的语法如下：

```cpp
for (declaration : expression)
    statement
```

在这里，`declaration`声明了一个变量，`expression`是一个序列（如数组或容器）。

`for`循环会遍历`expression`中的每个元素，并将每个元素的值赋给`declaration`。

然后，对于序列中的每个元素，都会执行一次`statement`。



例如，下面的代码会打印出数组中的所有元素：

```cpp
int arr[] = {1, 2, 3, 4, 5};
for(int i : arr) {
    std::cout << i << std::endl;
}
```

在这个例子中，`i`是声明的变量，`arr`是要遍历的序列。`for`循环会遍历`arr`中的每个元素，并将每个元素的值赋给`i`。





## while循环

`while` 循环是最基本的循环结构，它的格式如下：

```c++
while (条件表达式) {
    // 循环体
}
```



在 `while` 循环中，首先会检查条件表达式的值。如果条件表达式的值为 `true`，则执行循环体，然后再次检查条件表达式。

这个过程会一直重复，直到条件表达式的值为 `false`，此时循环结束。

例如，下面的代码会打印出数字 1 到 10：

```c++
int i = 1;
while (i <= 10) {
    cout << i << endl;
    i++;
}
```



## do while循环

`do while` 循环和 `while` 循环非常相似，但有一个关键的区别：`do while` 循环会先执行循环体，然后再检查条件表达式。

这意味着，无论条件表达式的值是什么，循环体至少会被执行一次。`do while` 循环的格式如下：

```c++
do {
    // 循环体
} while (条件表达式);
```



例如，下面的代码会打印出数字 1 到 10：

```c++
int i = 1;
do {
    cout << i << endl;
    i++;
} while (i <= 10);
```



## break 和 continue

`break`语句可以用来立即退出`for`循环，而`continue`语句可以用来跳过当前循环迭代的剩余部分，并立即开始下一次迭代。

```cpp
for(int i = 0; i < 10; i++) {
    if(i == 5) {
        break; // 当i等于5时，立即退出循环
    }
    if(i % 2 == 0) {
        continue; // 当i是偶数时，跳过循环的剩余部分
    }
    // 其他代码
}
```



## 复合语句

1. **每个复合语句中的变量具有自动存储生存周期**：在复合语句中声明的变量只在该复合语句的范围内有效。一旦超出该范围，这些变量就会被销毁。

```c++
{
    int x = 10;  // x只在这个复合语句中有效
    cout << x;  // 输出10
}  // x在这里被销毁
cout << x;  // 错误，x在这里不再有效
```



2. **复合语句支持多次嵌套**：你可以在一个复合语句中嵌套另一个复合语句，这被称为多次嵌套。

```c++
{
    int x = 10;
    {
        int y = 20;
        cout << x << " " << y;  // 输出10 20
    }
}
```



3. **复合语句中支持多个嵌套**：在一个复合语句中，你可以嵌套多个复合语句，这被称为多个嵌套。

```c++
{
    int x = 10;
    {
        int y = 20;
        cout << x << " " << y << endl;  // 输出10 20
    }
    {
        int z = 30;
        cout << x << " " << z << endl;  // 输出10 30
    }
}
```



在上述的多个嵌套示例中，`y`和`z`都是在各自的复合语句中声明的，因此它们的作用范围互不影响。


## 逗号运算符

语句块允许把两条或更多条语句放到按 C++句法只能放一条语句的地方。

逗号运算符对表达式完成同样的任务，允许将两个表达式放到C++句法只允许放一个表达式的地方。

例如，假设有一个循环每轮都将一个变量加 1，而将另一个变量减 1。

在 `for` 循环控制部分的更新部分中完成这两项工作将非常方便,但循环句法只允许这里包含一个表达式。

在这种情况下，可以使用逗号运算符将两个表达式合并为一个:

```c++
++j, --i; // 两个表达式在语法上被视为一个

for(int i,j;i<j;i++,j--){
    //循环语句
}
```



逗号并不总是逗号运算符。例如，下面这个声明中的逗号将变量列表中相邻的名称分开:

```c++
int i, j; // 这里的逗号是分隔符，不是运算符
```



逗号表达式的值总是最右边表达式计算出来的值，例如：

```
sum = (15+30,30+15,10+10);
//sum的值为20,即最后的10+10表达式计算出来的值
```



在所有运算符中，逗号运算符的优先级是最低的。例如，下面的语句:

```c++
cats = 17, 240;
//被解释为:
(cats = 17), 240;
//cats的值为17

//如果使用括号
cats = (17, 240);
//cats的值为240
```



逗号运算符是一个顺序点，也就是说首先计算左侧，并且在右侧被计算之前产生所有的副作用。

```cpp
j = 10;
j++,++j+1,++j;
//等价于
j++;
++j+1;
++j;
```



## 关系运算符

C++ 提供了 6 种关系运算符来对数字进行比较。由于字符用其 ASCII 码表示，因此也可以将这些运算符用于字符。

对于所有的关系表达式，如果比较结果为真，则其值将为 `true`（1），否则为 `false`（0）。

| 操作符 | 含义       |
| :----- | :--------- |
| `<`    | 小于       |
| `<=`   | 小于或等于 |
| `==`   | 等于       |
| `>`    | 大于       |
| `>=`   | 大于或等于 |
| `!=`   | 不等于     |



关系运算符的优先级比算术运算符低。

这意味着表达式 `x + 3 > y - 2` 对应于 `(x + 3) > (y - 2)`，而不是 `x + (3 > y) - 2`。



## 4. 字符函数库cctype

cctype 是 C++ 的一个标准库，它提供了一系列用于处理字符的函数。这些函数可以帮助我们确定字符的类型（如字母、数字、空白字符等），也常用于字符的处理和验证任务。

以下是 cctype 库中一些常用的函数：

- isalpha()：判断一个字符是否是字母（a-z 或 A-Z）。
- isdigit()：判断一个字符是否是数字（0-9）。
- isalnum()：判断一个字符是否是字母或数字（a-z、A-Z 或 0-9）。
- islower()：判断一个字符是否是小写字母（a-z）。
- isupper()：判断一个字符是否是大写字母（A-Z）。
- isspace()：判断一个字符是否是空白字符（空格、制表符、换行符等）。
- isblank()：判断一个字符是否是空白字符（空格或制表符）。
- ispunct()：判断一个字符是否是标点字符。
- isprint()：判断一个字符是否是可打印字符（非控制字符）。
- iscntrl()：判断一个字符是否是控制字符（非打印字符）。
- toupper()：将一个字符转换为大写字母。
- tolower()：将一个字符转换为小写字母。



所有这些函数都接受一个 int 类型的参数，这个参数是期望的字符的 ASCII 值。函数返回一个 int 类型的值，通常非零值表示真（true），零值表示假（false）。





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



## ？：运算符

在 C++ 中，?: 是一个条件运算符，也被称为三元运算符。它的格式如下：

```cpp
表达式1 ? 表达式2 : 表达式3
```

这个运算符的工作方式是：

首先计算 表达式1，如果 表达式1 的值为 true，则计算 表达式2 的值并返回；

如果 表达式1 的值为 false，则计算 表达式3 的值并返回。

例如，下面的代码会根据 x 的值来决定 y 的值：

```cpp
int x = 10;
int y = (x > 0) ? 1 : -1;  // 如果 x > 0，则 y 的值为 1，否则为 -1
```



可以嵌套使用条件运算符 `?:` 来实现更复杂的条件判断。嵌套使用意味着在 `表达式2` 或 `表达式3` 的位置再使用一个 `?:` 运算符。

下面是一个例子：

```c++
int x = 10, y = 20, z = 30;
int max = (x > y) ? ((x > z) ? x : z) : ((y > z) ? y : z);
```



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



# 字面值

## 整形

C++ 中的整型字面值可以以三种不同的基数来表示：10（十进制）、8（八进制）和 16（十六进制）。

无论整型字面值的表示基数是多少，它们都将**以二进制数（基数为 2）**的形式存储在计算机中。

C++ 使用数字常量的前一（两）位来标识基数。例如：

1. 如果第一位为 1~9，则基数为 10；
2. 如果第一位是 0，第二位为 1~7，则基数为 8；
3. 如果前两位为 0x 或 0X，则基数为 16。



在 C++ 中，对于不带后缀的整数，将使用能够存储该数的最小类型来表示

后缀是放在数字常量后面的字母，用于表示类型。例如：

1. **L 或 l**：表示该整数为 `long` 常量。
2. **u 或 U**：表示 `unsigned int` 常量。
3. **ul 或 UL**：表示 `unsigned long` 常量。
4. **ULL 或 ULL**：用于表示 `long long` 类型和 `unsigned long long` 类型。



## 浮点型

1. **默认情况**：像 `8.24` 和 `2.4E8` 这样的浮点常量默认为 `double` 类型。
2. **float 类型**：添加 `f` 或 `F` 后缀。
3. **long double 类型**：添加 `l` 或 `L` 后缀。



# 字符串

## 转义字符

有些字符不能直接通过键盘输入到程序中，或者它们在 C++ 语言中有特殊的含义。对于这些字符，C++ 提供了一种特殊的表示方法，称为转义序列。

- `\\`：表示一个反斜杠字符
- `\"`：表示一个双引号字符
- `\'`：表示一个单引号字符
- `\n`：表示一个换行符
- `\t`：表示一个制表符
- `\a`：表示一个振铃字符，它可以使终端扬声器振铃



## 通用字符名

通用字符名的用法类似于转义序列，可以以 `u` 或 `\U` 打头，后面是 8 个或 16 个十六进制位。

```
char c1 = '\u0065'; // 'e' 的 Unicode 码点是 0065
char c2 = '\u0066'; // 'f' 的 Unicode 码点是 0066
char c3 = '\u0067'; // 'g' 的 Unicode 码点是 0067

wchar_t wc1 = L'\u03B1'; // 希腊字母 'α' 的 Unicode 码点是 03B1
wchar_t wc2 = L'\u03B2'; // 希腊字母 'β' 的 Unicode 码点是 03B2
wchar_t wc3 = L'\u03B3'; // 希腊字母 'γ' 的 Unicode 码点是 03B3
```



# 函数

## 函数格式

- typeName：函数返回值类型，可为void（无返回值函数）
- functionName：函数名
- parameterList：参数列表，可为void（无参数函数）
- return：对于void（空函数）return语句是可选的，有返回值的函数必须返回一个typeName 类型或可以被转换为 typeName 类型的值。

```cpp
typeName functionName(parameterList) {
    // 函数体
    // return; 对于无返回值（void类型）的函数，return是可选的
    return value;  // value 的类型必须为 typeName 类型或可以被转换为 typeName 类型
}
```

​	

## 函数原型

原型描述了函数到编译器的接口，也就是说，它将函数返回值的类型(如果有的话)以及参数的类型和数量告诉编译器。

获得原型最简单的方法是，复制函数定义中的函数头，并添加分号。

一个完整的原型包含三个部分：函数名、返回值类型、参数列表。

```cpp
int functionName(int var1,int var2);
```

对于上面的函数原型，三个部分为：

函数名：表示函数的名称为functionName。

返回值类型：表示函数返回一个int类型的值。

参数列表：表述函数接受两个int类型的参数。



## 形参和实参数

在函数定义中，用于接收传递值的变量被称为形参（parameter）。传递给函数的值被称为实参（argument）。因此，参数传递就是将实参的值赋给形参。



## 局部变量和自动变量

在函数中声明的变量（包括形参）被称为局部变量，因为它们只在函数内部有效。当函数被调用时，计算机会为这些变量分配内存；当函数结束时，计算机会释放这些变量占用的内存。这样的变量也被称为自动变量，因为它们是在程序执行过程中自动被创建和销毁的。



## 数组作为参数传递

在 C++ 中，当我们将数组名作为函数参数时，实际上传递的是数组的地址，也就是指向数组第一个元素的指针。

`int *arr`和`int arr[]`在参数列表的作用是相同的，而`int arr[10]`不允许出现在函数参数列表中。

函数接收到的是指向数组第一个元素的指针，而不是整个数组（的副本）。

如果在被调函数中修改了数组的值，在调用函数中数组的值一样发生了变化。

这样做的好处是可以节省复制整个数组所需的时间和内存，也意味着在函数内部无法直接获取到数组的长度，因此通常需要额外传递一个表示数组长度的参数。

```cpp
double getAverage(int* arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; ++i) {
        sum += arr[i];
    }
    return double(sum) / size;
}
```



所有类型的数组都是如此，包括char类型的数组字符串，如果想在传输的过程中将整个数组（或字符串）的内容复制到被调函数中（生成一个副本），可以考虑模板类array和string对象。



## 结构作为参数传递

在 C++ 中，当我们将结构体作为函数参数时，会生成该结构体的一个副本。这意味着函数会接收到一个新的结构体，它与原始结构体有相同的值，但在内存中的位置不同。这种方式被称为按值传递。

复制整个结构体会增加时间和内存的消耗，特别是当结构体很大时。因此，我们可以考虑使用指针来传递结构体。



**示例1：按值传递结构体**

```cpp
#include <iostream>
using namespace std;

struct Point {
    double x;
    double y;
};

// 按值传递结构体
void printPoint(Point p) {
    cout << "Point: (" << p.x << ", " << p.y << ")" << endl;
}

// 按值返回结构体
Point getOrigin() {
    Point origin = {0, 0};
    return origin;
}

int main() {
    Point p = {3.5, 4.2};
    printPoint(p);  // 按值传递结构体
    p = getOrigin();  // 按值返回结构体
    printPoint(p);
    return 0;
}

```



**示例2：按址传递结构体**

```cpp
#include <iostream>
using namespace std;

struct Point {
    double x;
    double y;
};

// 按址传递结构体
void movePoint(Point* p, double dx, double dy) {
    p->x += dx;
    p->y += dy;
}

// 按址返回结构体
Point* createPoint(double x, double y) {
    Point* p = new Point;
    p->x = x;
    p->y = y;
    return p;
}

int main() {
    Point* p = createPoint(3.5, 4.2);  // 按址返回结构体
    movePoint(p, 1.0, -0.5);  // 按址传递结构体
    cout << "Point: (" << p->x << ", " << p->y << ")" << endl;
    delete p;
    return 0;
}
```



在 C++ 中，当我们将普通数组作为函数参数时，实际上是传递的数组的地址。

`std::array` 是一个包装固定大小数组的容器，它包含了一些有用的函数，如 size()，可以返回数组的长度。当我们将 std::array 作为函数参数时，如果是按值传递，会复制整个 std::array 对象。



**示例1：按值传递普通数组**

```cpp
#include <iostream>
using namespace std;

void printArray(int arr[], int size) {
    for (int i = 0; i < size; ++i) {
        cout << arr[i] << " ";
    }
    cout << endl;
}

int main() {
    int arr[] = {1, 2, 3, 4, 5};
    printArray(arr, 5);  // 传递数组的地址和长度
    return 0;
}
```





**示例2：按值传递 `std::array`**

```cpp
#include <iostream>
#include <array>
using namespace std;

void printArray(array<int, 5> arr) {
    for (int i = 0; i < arr.size(); ++i) {
        cout << arr[i] << " ";
    }
    cout << endl;
}

int main() {
    array<int, 5> arr = {1, 2, 3, 4, 5};
    printArray(arr);  // 复制并传递整个 std::array 对象
    return 0;
}
```



## 递归

递归是一种编程技术，函数在其定义中调用自身，这种过程称为递归。递归函数通常由以下两个部分组成：

- 基本情况（Base Case）：这是递归的终止条件。没有基本情况，递归函数将无限地调用自己，导致栈溢出。
- 递归情况（Recursive Case）：在这里，函数将问题分解成更小的子问题，并自我调用来解决这些子问题。

**7.9.1 包含一个递归调用的递归**

这种类型的递归在每个递归级别只进行一次递归调用。例如，计算阶乘（n!）是递归的经典应用之一。以下是求 n! 的递归函数的 C++ 实现：

```cpp
#include <iostream>
int factorial(int n) {
    // 基本情况
    if (n == 0) {
        return 1;
    }
    // 递归情况
    return n * factorial(n - 1);
}
int main() {
    int result = factorial(5); // 5的阶乘是120
    std::cout << "Factorial of 5 is: " << result << std::endl;
    return 0;
}
```



**7.9.2 包含多个递归调用的递归**

这种类型的递归在每个递归级别进行多次递归调用。例如，计算斐波那契数列的第 n 个元素是递归的另一个经典例子。以下是计算斐波那契数列的第 n 个元素的 C++ 实现：

```cpp
#include <iostream>
int fibonacci(int n) {
    // 基本情况
    if (n == 0) return 0;
    if (n == 1) return 1;
    // 递归情况
    return fibonacci(n - 1) + fibonacci(n - 2);
}
int main() {
    int result = fibonacci(5); // 第5个Fibonacci数是5
    std::cout << "The 5th Fibonacci number is: " << result << std::endl;
    return 0;
}
```



## 函数指针

与数据项相似，函数也有地址。函数的地址是存储其机器语言代码的内存的开始地址（用于调用这个函数）。

例如，可以编写将另一个函数的地址作为参数的函数。这样第一个函数将能够找到第二个函数，并运行它。

与直接调用另一个函数相比，这种方法很笨拙，但它允许在不同的时间传递不同函数的地址，这意味着可以在不同的时间使用不同的函数。



### 1. 获取函数的地址

获取函数的地址很简单：只要使用函数名（后面不跟参数）即可

如果 think() 是一个函数则 think 就是该函数的地址。

```
process(think);
thought(think());
```

process()调用使得 process()函数能够在其内部调用 think()函数。

thought()调用首先调用 think()函数，然后将 think()的返回值传递给 thought()函数。



### 2. 声明函数指针

声明指向函数的指针时，应指定函数的返回类型以及函数的特征标(参数列表)。

函数原型：

```cpp
double pam(int);
```

声明函数指针：

```cpp
double (*pf)(int);
```



### 3. 使用指针来调用函数
即使用指针来调用被指向的函数。线索来自指针声明。

`(*pf)`扮演的角色与函数名相同，因此使用`(*pf)`时，只需将它看作函数名即可:

```
double pam(int);
double(*pf)(int);
pf = pam;
double x=pam(4);
double y=(*pf)(5);
```

实际上，C++也允许像使用函数名那样使用pf：

```
double y=pf(5);
```

第一种格式虽然不太好看，但它给出了强有力的提示——代码正在使用函数指针。



一种学派认为，由于 pf是函数指针，而`*pf`是函数,因此应将`(*pf)()`用作函数调用。另一种学派认为，由于函数名是指向该函数的指针，指向函数的指针的行为应与函数名相似，因此应将 `pf()`用作函数调用使用。C++进行了折衷——这2种方式都是正确的。



### 代码示例

```cpp
// fun ptr.cpp --pointers to functions
#include <iostream>

double betsy(int);
double pam(int);

// second argument is pointer to a type double function that
// takes a type int argument
void estimate(int lines, double(*pf)(int));

int main() {
    using namespace std;
    int code;

    cout << "How many lines of code do you need? ";
    cin >> code;

    cout << "Here's Betsy's estimate:\n";
    estimate(code, betsy);	//第一次被调函数中调用betsy函数

    cout << "Here's Pam's estimate:\n";
    estimate(code, pam);	//第二次被调函数中调用pam函数

    return 0;
}

double betsy(int lns) {
    return 0.05 * lns;
}

double pam(int lns) {
    return 0.03 * lns + 0.0004 * lns * lns;
}

void estimate(int lines, double(*pf)(int)) {
    using namespace std;

    cout << lines << " lines will take ";
    cout << (*pf)(lines) << " hour(s)\n";
}

```



## 使用`typedef` 进行简化

关键字 `typedef` 能够创建类型别名:

```cpp
typedef double real; // makes real another name for double
```



这里采用的方法是，将别名当做标识符进行声明，并在开头使用关键字 `typedef`。

因此，可将 `pfun` 声明为函数指针类型的别名:

```cpp
typedef const double *(*pfun)(const double *, int); // pfun now a type name
pfun pl = fl; // pl points to the f1() function
```



然后使用这个别名来简化代码:

```cpp
pfun pa[3] = {fl, f2, f3}; // pa an array of 3 function pointers
pfun (*pd)[3] = &pa; // pd points to an array of 3 function pointers
```



使用 `typedef` 可减少输入量，让您编写代码时不容易犯错，并让程序更容易理解。



## 内联函数inline

内联函数是C++为提高程序运行速度所做的一项改进。

内联函数的编译代码与其他程序代码“内联”起来了。也就是说，编译器将使用相应的函数代码替换函数调用。

对于内联代码,程序无需跳到另一个位置处执行代码,再跳回来。

因此，内联函数的运行速度比常规函数稍快，但代价是需要占用更多内存。



这是一个C++内联函数的例子，该函数用于计算一个数的平方：

```cpp
inline double square(double x) {
    return x * x;
}
```

在这个例子中，`square`函数被声明为`inline`，这意味着每次函数被调用时，编译器会用函数体替换函数调用，而不是按照通常的方式跳转到函数，执行函数，然后跳回。



在C语言中，我们使用预处理器语句#define来提供宏，这是内联代码的原始实现。例如，下面是一个计算平方的宏：

```cpp
#define SQUARE(X) X*X
```



这并不是通过传递参数实现的，而是通过文本替换来实现的。例如：

```cpp
a = SQUARE(5.0); // 替换后为：a = 5.0*5.0;
b = SQUARE(4.5 + 7.5); // 替换后为：b = 4.5 + 7.5 * 4.5 + 7.5;
d = SQUARE(c++); // 替换后为：d = c++ * c++;
```



在上述示例中，只有第一个能正常工作。我们可以通过使用括号来进行改进：

```cpp
#define SQUARE(X) ((X)*(X))
```



但仍然存在这样的问题，即宏不能按值传递。即使使用新的定义，`SQUARE(c++)`仍将c递增两次。但是，如果我们使用C++的内联函数，就可以按值传递参数，这使得C++的内联功能远远胜过C语言的宏定义。例如，我们可以定义一个内联函数`square()`来计算c的平方，然后将c递增一次。

这里的目的不是演示如何编写C宏，而是要指出，如果使用C语言的宏执行了类似函数的功能，应考虑将它们转换为C++内联函数。



# 引用变量

引用是已定义的变量的别名(另一个名称)。

例如,如果将twain作为 clement变量的引用，则可以交替使用twain 和 clement来表示该变量。

引用变量的主要用途是用作函数的形参。通过将引用变量用作参数，函数将使用原始数据，而不是其副本。

这样除指针之外，引用也为函数处理大型结构提供了一种非常方便的途径，同时对于设计类来说，引用也是必不可少的。



C和C++使用&符号来指示变量的地址。

C++给&符号赋予了另一个含义，将其用来声明引例如，要将rodents作为rats变量的别名，可以这样做：。

```cpp
int rats;
int & rodents = rats;  //引用变量只能（也必须）使用初始化指定，如果没有初始化则编译无法通过
```

可以这样子使用引用变量

```cpp
#include <iostream>

using std::cout;
using std::endl;

int main(void) {

	int rats = 10;
	int& rodents = rats;

	cout << "rats\t= " << rats << endl;
	cout << "rodents\t= " << rodents << endl;

	rats++;
	cout << "rats\t= " << rats << endl;
	cout << "rodents\t= " << rodents << endl;

	rodents++;
	cout << "rats\t= " << rats << endl;
	cout << "rodents\t= " << rodents << endl;

	cout << "rats address\t= " << &rats << endl;
	cout << "rodents address\t= " << &rodents << endl;

}
```

执行结果：	

```
rats    = 10
rodents = 10
rats    = 11
rodents = 11
rats    = 12
rodents = 12
rats address    = 00000083225CFCD4
rodents address = 00000083225CFCD4
```

修改rats会影响rodents，相反也是一样的结果，且它们两个的地址相同。



## 函数中的引用变量

以下的程序中使用了按引用进行值传递的方式，来交换两个参数的值：

```cpp
#include <iostream>

using std::cout;
using std::endl;

void changeValue(int & a, int & b) {
	
    //由于是使用的引用变量，在被调函数中修改值，会影响到调用函数中的值。
	int temp = a;
	a = b;
	b = temp;
	return;

}

int main(void) {

	int min = 1, max = 10;
	cout << "min = " << min << endl;
	cout << "max = " << max << endl;
	changeValue(min, max);
	cout << "min = " << min << endl;
	cout << "max = " << max << endl;

	return 0;
}
```



## 临时变量和const

如果实参与引用参数不匹配，编译器将不会通过编译，除非使用了const引用，编译器将会创建一个临时变量，然后引用这个临时变量。

如果引用参数是const，则编译器将在下面两种情况下生成临时变量：

- 实参的类型正确，但不是左值。（将 a + 10 传递给引用变量，a 和 引用变量 都为 int 类型 ）
- 实参的类型不正确，但可以转换为正确的类型。（将long类型变量，传递给int类型的引用变量）



```cpp
#include <iostream>

using std::cout;
using std::endl;

void valuePrint(const int& x) {

	cout << "x = " << x << endl;

	return;
}

int main(void) {

	{
        // 对于第一种情况
		int a = 10;
		valuePrint(a + 20);
	}

	{
        // 对于第二种情况，则可能会出现溢出问题
        // int 类型为 4字节，其有符号范围为 -2147483648到2147483647。
        // long long int 类型为 8 字节
        // 虽然类型不匹配会生成临时变量，但是生成的临时变量是int类型，2147483648超出了范围，发生了溢出情况。
		long long int a = 2147483648;
		valuePrint(a);
	}

	return 0;
}
```



对于当前的C++标准，必须是const引用变量才会创建临时变量，而对于一些旧的编译器，则允许非const也创建临时变量。

为什么现在要允许const引用变量，而不允许非const呢？

```cpp
#include <iostream>

using std::cout;
using std::endl;

void valueChange(int& a ,int & b) {

	int temp = a;
	a = b;
	b = temp;

	return;
}

int main(void) {

	long long int x = 10, y = 20;
	cout << "x = " << x << endl;
	cout << "y = " << y << endl;
	valueChange(x, y);
	cout << "x = " << x << endl;
	cout << "y = " << y << endl;

	return 0;
}
```

允许结果：

```
x = 10
y = 20
x = 10
y = 20
```

为什么没有引用变量没有交换x和y变量的值呢？

因为long long int 和 int类型不同，所以创建的临时变量，在valueChange函数中a和b引用变量，引用的不是main函数中x和y的值，而是两个临时变量的值。

所以valueChange函数在交换a和b变量的值，实际上交换的是两个临时变量的值，而不是main函数中x和y的值，所以main函数中x和y的值没有被改变。



当前已经不允许这种非const的方式，必须使用const才能通过编译，const使得无法修改引用变量（两个被创建的临时变量）的值，就不会出现这样的情况。



**尽量使用const引用变量**：

- 将引用参数声明为常量数据的引用的理由有三个。
- 使用 const 可以避免无意中修改数据的编程错误。
- 使用 const使函数能够处理 const和非 const 实参，否则将只能接受非 const数据。



## 右值引用的基本概念
在C++中，我们通常将值分为左值和右值。

左值是表达式（不一定是赋值表达式）后依然存在的持久对象，是拥有身份且不可被移动的表达式。

右值是表达式结束后就不再存在的临时对象。

右值引用就是用来引用这些临时对象的。它们使用&&声明，例如：

```
int && r = 1;
```

这里的r就是一个右值引用，它引用了右值1。



## 函数返回常规变量和引用的区别

在返回常规变量时，一般都是将其值复制到一个临时的内存空间中去，该临时的内存空间只能成为右值，且被使用后立马释放。



```cpp
int& valueCopy(int& target, int& source) {

	target = source;

	return target;
	// 只看target是无法确定返回的是常规变量还是引用变量
    // 如果返回值类型为int，则是将target的值复制到一个临时的内存空间中去
    // 如果返回值类型为int & ，则是将target（或者说x）变量引用返回，可以通过这个引用修改x的值。
}
```

与其他常规函数不同，该函数的返回值类型为`int &`，也就是说函数返回的是一个int类型的引用。

在valueCopy函数中假设传递的参数是main函数中的x和y变量，对应valueCopy函数中的target和source变量，该函数返回的是target变量的引用，相当于返回main函数中x变量的引用，于是可以进行以下操作：

```cpp
int z = valueCopy(x,y);	// 引用target变量，相当于引用x变量。
int z = 20;				// 修改z变量的值，x的值也被修改。
valueCopy(x,y) = 30;	// 该操作也是合法的，因为返回的值x变量的引用，相当于修改x的值
```



将设要通过引用使用返回值，但又不允许通过这个引用来改变其值，还不想使用临时变量，则可以声明为const引用。

```cpp
const int& valueCopy(int& target, int& source) {
	target = source;
	return target;
}
```

只能使用引用变量的值，而不能修改其中的值：

```cpp
valueCopy(x,y) = 30; 			//非法

int temp = valueCopy(x,y)		//合法

int & z = valueCopy(x,y);		//非法

const int & z = valueCopy(x,y)	//合法
z = 30;							//非法
const int temp = z;				//合法
```



不要返回函数中局部变量的引用（因为在函数结束后局部变量会被释放）：

```cpp
int& valueCopy(int& source) {
	int target = source;
	return target;
}
```



但是可以在函数中new内存空间，使用指针指向它，并返回它的引用：

```cpp
int& valueCopy(int& source) {
	int *target = new int;
	*target = source
	return *target;
}
```



## 类引用

基类引用可以指向派生类对象



## 默认参数

在C++中，函数参数可以有默认值。这意味着当调用函数时，如果没有提供某个参数的值，那么将使用该参数的默认值。

```cpp
#include <iostream>

using std::cout;
using std::endl;

void display(int n = 1) {

	cout << "n = " << n << endl;

	return ;
}
int main(void) {

	display();
	display(10);

	return 0;
}
```

对于带参数列表的函数，必须从右向左添加默认值。

要为某个参数设置默认值，则必须为它右边的所有参数提供默认值（正确示范）：

```cpp
void display(int n = 1) { ... }
void display(int x = 1 , int y = 2 , int z = 3) { ... }
void display(int x , int y = 2 , int z = 3){ ... }
void display(int x , int y , int z = 3) { ... }
```

假设要为参数y设置默认参数，则必须为y右边的所有参数设置默认值（错误示范）：

```cpp
void display(int x , int y = 2 , int z){...}
```



假设只有函数定义，而没有函数声明，则只需（也只能）在函数定义中给出默认参数，例如上面的完整参数的情况。



假设既有函数定义，又有函数声明，则必须在函数声明中给出默认参数。

示例1：只在函数定义中给出默认参数，没有在函数声明中给出。

结果：编译无法通过，报错信息为"display函数不接收0个参数"。

```cpp
void display(int n); //函数声明中没有指定。

int main(void) {
	display(); //函数中没有提供参数
	return 0;
}

void display(int n = 1) { //函数定义中给出默认参数。
	cout << "n = " << n << endl;
	return;
}
```



示例2：在函数定义和函数声明中都给出了默认参数。

结果：编译无法通过，报错信息为"重定义默认参数，参数1"。

```cpp
void display(int n = 1);//函数声明中给出默认参数。

int main(void) {
	display();//函数中没有提供参数
	return 0;
}

void display(int n = 1) {//函数定义中给出默认参数。
	cout << "n = " << n << endl;
	return;
}
```



示例3：在函数定义中没有给出默认参数，在不同的函数声明中给出不同的默认参数。

运行结果：

```
n = 1
n = 100
```

```cpp
int main(void) {

	{
		void display(int n = 1);//此处函数声明指定n的默认参数为1
		display();
	}

	{
		void display(int n = 100);//此处函数声明指定n的默认参数为100
		display();
	}

	return 0;
}

void display(int n) {//函数定义中没有指定默认参数

	cout << "n = " << n << endl;

	return;
}
```



# 函数重载

函数重载的关键是函数的参数列表——也称为函数特征标(fiunction signature)。

如果两个函数的参数数目和类型相同，同时参数的排列顺序也相同，则它们的特征标相同，而变量名是无关紧要的。

C++允许定义名称相同的函数，条件是它们的特征标不同。如果参数数目和/或参数类型不同，则特征标也不同。



 例如，定义一组原型如下的`print()`函数：

```cpp
void print(float d, int width);
void print(int i, int width);
void print(char *str);
```

使用`print()`函数时，编译器将根据所采取的用法使用有相应特征标的原型：

```cpp
print("hello");		// #3
print(1.0,2);		// #1
print(2,10);		// #2
```



## 强制匹配

### 示例1：提升匹配

如果当前类型不于任何一个重载匹配，则会尝试使用标准类型转换进行强制匹配，例如float可以转化为double，所以main函数中的print调用会匹配到`void print(double);`

```cpp
void print(double x) {
	cout << x << endl;
}

void print(int x) {
	cout << x << endl;
}


int main(void) {

	float x = 10;
	print(x);

	return 0;
}

```



### 示例2：提升匹配重复

如果是下面这种情况，int类型既可以提升为float，也可以提升为double，所以无法进行匹配：

```cpp
void print(double x) {
	cout << x << endl;
}

void print(float x) {
	cout << x << endl;
}


int main(void) {

	int x = 10;
	print(x);

	return 0;
}

```



### 示例3：不能降级匹配

在强制匹配时，只会使用提示匹配，而不会使用降级匹配，在下面这个例子中，如果将double降低为float进行匹配，会导致精度丢失，所以不会匹配成功：

```cpp
void print(float x) {
	cout << x << endl;
}

void print(int x) {
	cout << x << endl;
}


int main(void) {

	double x = 10;
	print(x);

	return 0;
}
```



如果没有不是函数重载，而只是降级，则可以编译通过，但还是会存在精度丢失问题：

```cpp
void print(float x) {
	cout << x << endl;
}

int main(void) {

	double x = 10;
	print(x);

	return 0;
}
```







### 示例4：引用变量特征标

一些看起来彼此不同的特征标是不能共存的。例如，请看下面的两个原型：

```
double cube(double x);double cube(double &x);
```

它们的特征标看起来不同，假设有下面这样的代码:

```
cout << cube(x);
```

参数x与 `double x`原型和 `double &x`原型都匹配，因此编译器无法确定究竟应使用哪个原型。

为避免这种混乱，编译器在检查函数特征标时，将把**类型引用和类型本身视为同一个特征标**。



### 示例5：引用匹配

首先，右三个函数原型：

```cpp
void sink(double &r1);  // 匹配可修改的左值
void sank(const double &r2);  // 匹配可修改的左值、const左值或右值
void sunk(double &&r3);  // 匹配右值
```

- `sink`函数接受一个可修改的左值引用
- `sank`函数接受一个const左值引用
- `sunk`函数接受一个右值引用



重载了这三种参数类型的函数，编译器会选择最匹配的版本。

```cpp
void stove(double &rl);  // 匹配可修改的左值
void stove(const double &r2);  // 匹配const左值或右值
void stove(double &&r3);  // 匹配右值
```

- 如果有一个可修改的左值`x`，那么调用`stove(x)`会选择`stove(double &rl)`版本；
- 如果有一个const左值`y`，那么调用`stove(y)`会选择`stove(const double &r2)`版本；
- 如果有一个右值`x+y`，那么调用`stove(x+y)`会选择`stove(double &&r3)`版本；
- 如果没有定义`stove(double &&)`，那么`stove(x+y)`将会调用`stove(const double &)`版本。



### 示例5：函数重载和默认参数

假设函数重载中还有默认参数，则可能涉及到这种问题：

```cpp
void print(int n, double x = 10.10) { ... }
void print(int n, char x = 'c') { ... }
void print(int n) { ... }
```

这种情况下`void print(int)`是无论如何都无法被匹配，如果没有这一条，`print(1);`也无法匹配到任何函数。

`print(1,10.0);`匹配到`void print(int,double);`因为浮点型默认为double

`print(1,10.0f);`匹配到`void print(int,float);`因为使用后缀指定为float类型



# 函数模板

函数模板是一种特殊的函数，可以处理不同的数据类型，但是处理方式相同。这种函数的定义方式称为函数模板。

函数模板的定义格式如下：

```cpp
template <typename T>
函数返回类型 函数名(参数列表)
{
    // 函数体
}
```



其中，`template <typename T>`是模板声明，表示声明一个模板，`T`是类型参数，可以用来代表任何类型。

在标准 C++98 添加关键字 typename 之前，C++使用关键字 class 来创建模板。

下面是一个使用函数模板来交换两个`int`和`double`类型的值的示例：

```cpp
template <typename T>
void swap(T& a, T& b) {
    T temp = a;
    a = b;
    b = temp;
}

int main() {
    int i1 = 1, i2 = 2;
    double d1 = 1.1, d2 = 2.2;
    swap(i1, i2);  // 交换两个int类型的值
    swap(d1, d2);  // 交换两个double类型的值
    return 0;
}
```



## 模板重载

模板重载是一种在C++中使用模板的高级技术，它允许我们为不同的类型或参数定义不同的模板函数。

有两个`Swap`函数模板，第一个模板用于交换两个值，而第二个模板用于交换两个数组中的元素。这两个模板的函数特征标是不同的，所以它们可以同时存在。

第一个模板的函数特征标为`(T&, T&)`，它接受两个引用参数，用于交换两个值：

```cpp
template <typename T>
void Swap(T &a, T &b) {
    T temp = a;
    a = b;
    b = temp;
}
```



第二个模板的函数特征标为`(T[], T[], int)`，它接受两个数组和一个整数，用于交换两个数组中的元素：

```cpp
template <typename T>
void Swap(T *a, T *b, int n) {
    for (int i = 0; i < n; i++) {
        T temp = a[i];
        a[i] = b[i];
        b[i] = temp;
    }
}
```



## 模板的局限性

模板也有其局限性：

1. **类型限制**：模板函数假定可以对其类型参数执行某些操作。例如，如果你的模板函数中有一个赋值操作`a = b`，那么这个模板就不能用于数组类型，因为数组不支持赋值操作。
2. **操作符限制**：模板函数可能会假定其类型参数支持某些操作符。例如，如果模板函数中有一个比较操作`if (a > b)`，那么这个模板就不能用于结构类型，因为结构类型默认不支持`>`操作符。
3. **通用性与特殊性的冲突**：有时，我们希望模板能够处理一些特殊的情况，但是C++的语法可能不允许。例如，我们可能希望一个模板函数能够处理两个包含位置坐标的结构的相加操作，但是C++默认并不支持结构的加法操作。

为了解决这些问题，C++提供了一些解决方案：

- **运算符重载**：我们可以为特定的结构或类重载某些运算符，使得模板函数可以处理这些类型。例如，我们可以重载`+`运算符，使得模板函数可以处理包含位置坐标的结构的相加操作。
- **模板特化**：我们可以为特定的类型提供具体化的模板定义，以处理这些类型的特殊情况。例如，我们可以为数组类型提供一个特化的模板，以处理数组的赋值操作。



## 显示具体化

我们为某个特定类型提供一个特殊的模板实现时，我们称之为显式具体化。

例如，假设我们有一个模板函数`print`，用于打印各种类型的值：

```cpp
template <typename T>
void print(const T& value) {
    std::cout << value << std::endl;
}
```



这个模板函数可以打印任何类型的值，只要这个类型支持`<<`操作符。然而，如果我们想要为`std::vector`类型提供一个特殊的打印方式，我们就可以使用显式具体化：

```cpp
template <>
void print(const std::vector<int>& vec) {
    for (const auto& value : vec) {
        std::cout << value << ' ';
    }
    std::cout << std::endl;
}
```



在这个显式具体化的版本中，我们遍历`std::vector`，并打印出每个元素。注意，显式具体化的模板前面有一个额外的`<>`，这是显式具体化的标志。

当我们调用`print`函数时，如果参数是`std::vector<int>`类型，编译器就会选择显式具体化的版本。如果参数是其他类型，编译器就会选择通用的模板版本。



## 隐式实例化、显式实例化、显式具体化

1. **隐式实例化**：当我们在代码中使用模板函数或模板类时，编译器会根据我们提供的类型参数，自动生成一个特定的函数或类。例如，如果我们有一个模板函数`Swap<T>(T&, T&)`，当我们调用`Swap<int>(int&, int&)`时，编译器就会生成一个处理`int`类型的`Swap`函数。
2. **显式实例化**：这是我们明确告诉编译器要生成某个特定类型的模板实例。例如，`template void Swap<int>(int, int);`就是一个显式实例化的声明，它告诉编译器我们希望生成一个处理`int`类型的`Swap`函数。

3. **具体化**：是为特定类型提供特殊的模板实现。例如，`template <> void Swap<int>(int&, int&);` 是一个显式具体化的`Swap`函数，专为`int`类型设计。



## decltype关键字

1. **基本用法**：`decltype`是一个关键字，用于推导表达式的类型。例如：

    ```cpp
    int a = 10;
    decltype(a) b = 20;  // b的类型为int
    ```

    在这个例子中，`decltype(a)`会得出`a`的类型为`int`，因此`b`的类型也为`int`。

    

2. **函数返回类型**：如果表达式是一个函数调用，`decltype`会得出函数的返回类型。例如：

    ```cpp
    double func();
    decltype(func()) x;  // x的类型为double
    ```

    注意，`decltype`并不会实际调用函数，它只是分析函数的返回类型。

    

3. **左值和右值**：如果表达式是一个左值，且被括号包裹，`decltype`会得出一个引用类型。例如：

    ```cpp
    int a = 10;
    decltype((a)) b = a;  // b的类型为int&
    ```

    在这个例子中，`(a)`是一个左值，因此`decltype((a))`得出的类型为`int&`。

    

4. **模板中的应用 - 后置返回类型**：后置返回类型（Trailing Return Type）。这种语法允许我们在函数声明中延迟指定返回类型。

5. 使用后置返回类型，可以在函数参数列表之后，使用 auto 关键字来指定函数的返回类型，从而使得返回类型可以依赖于函数参数或其他上下文信息。

    后置返回类型的语法格式如下：

    ```cpp
    auto FuncName(ArgsList) -> ReturnType { }
    ```

    例如，你可以使用后置返回类型来定义一个模板函数，该函数的返回类型依赖于模板参数2：

    ```cpp
    template<typename ArgType1, typename ArgType2>
    auto Func1(ArgType1& a, ArgType2& b) -> decltype(a + b) {
        return (a + b);
    }
    ```

    在这个例子中，decltype(a + b) 是一个表达式，它的类型就是 a + b 的类型。因此，Func1 的返回类型就是 a + b 的类型2。



# 左值和右值

在C语言和C++中，我们通常将值分为左值和右值。以下是关于左值和右值的详细解释：

## 左值（Lvalue）
左值（Lvalue）是指向内存区域的对象，左值可以出现赋值表达式的左边或右边。左值是可寻址的变量，有持久性。例如，如果arr是一个数组，那么arr[1]和*(arr+1)都将被视为相同内存位置的“名称”。

```
int x = 5; // x 是 左值
int arr[10]; // arr 是 左值
```



## 右值（Rvalue）
右值（Rvalue）则是指没有名字或地址的临时值或字面常量，例如数字，字符串或表达式。右值一般是不可寻址的常量，或在表达式求值过程中创建的无名临时对象，短暂性的。

```
int x = 1 + 2; // 1 + 2 是右值
```

在C++11中，右值的概念被进一步细分为纯右值（Prvalue）和将亡值（Xvalue）。纯右值是指非引用返回的临时对象或运算表达式，如1+2；将亡值是指生命周期即将结束的对象，通常是函数返回的引用。



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



