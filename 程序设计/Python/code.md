# python code

python有两种方式存放编码（字符串），一种是以字符（char）的方式来存放编码，一种是以字节（bytes）的方式来存放编码。

直接赋值的字符和字节编码，默认使用 UTF-8 进行存储。

字符编码：

```
s = "hello world 你好 世界"
```

字节编码：

```
b'hello wordl \xe4\xbd\xa0\xe5\xa5\xbd \xe4\xb8\x96\xe7\x95\x8c'
```



字节编码中，**只能使用 ASCII 字符**，如果确实需要包含**非 ASCII 字符**，可以**使用转义字符**。

转义字符是一种特殊字符，它以反斜杠（`\`）开始，用来表示那些不能直接输入的字符或者具有特定功能的字符。



字符编码还是字节编码。

**字符编码**用于表示文本数据，将字符转换为数字代码，以便计算机能够处理。

**字节编码**用于处理二进制数据，将字符编码转换为字节序列，以便在网络传输、文件存储等场景中使用。



## encode

**`encode()`**方法接受给定的字符串并返回该字符串的（字节）编码版本。

将字符串转为特定的字符编码，然后转换为字节编码。

Syntax 句法

```python
string.encode(encoding='encoding', errors='errors')
```

`string` （必需）：要编码的字符串。

`encoding` （可选）：要使用的编码类型。例如，某些编码类型是 UTF-32、ASCII、Base64 和 UTF-16。如果未指定，则将使用 UTF-8。

`errors` （可选）：如果字符串无法编码，如何处理错误。有六种错误响应：

- `strict` ：失败时将引发`UnicodeDecodeError` 。如果未指定错误处理，则这是默认值。
- `ignore` ：忽略无法编码的字符。
- `replace` ：将无法编码的字符替换为问号。
- `xmlcharrefreplace` ：如果存在无法编码的字符，则将在其位置插入 XML 字符引用。
- `backslashreplace` ：如果存在无法编码的字符，则将在其位置插入`\uNNNN`字符。
- `namereplace` ：如果存在无法编码的字符，则将在其位置插入`\N{...}`字符。



示例：

```python
s = "hello world"
s.encode()
# 返回 s 的字节编码（UTF-8）
# b'hello world'

s = "你好"
s.encode()
#  返回 s 的字节编码（UTF-8）
# b'\xe4\xbd\xa0\xe5\xa5\xbd'

s = "你好"
s.encode(encoding="gbk")
#  返回 s 的字节编码（GBK）
# b'\xc4\xe3\xba\xc3'
```

```python
example_a = 'Lèarning Pythön!'
example_b = 'Consistèntly!'

default_example = example_a.encode()
ascii_example = example_b.encode(encoding='ascii', errors='xmlcharrefreplace')

print("Default example:", default_example)
print("ASCII example:", ascii_example)

# Default example: b'L\xc3\xa8arning Pyth\xc3\xb6n!'
# ASCII example: b'Consist&#232;ntly!'
```



## decode

python 字符串**decode()**方法将字节编码解码成字符编码。

Syntax 句法

```python
string.encode(encoding='encoding', errors='errors')
```



`string` （必需）：要编码的字符串。

`encoding` （可选）：要使用的编码类型。默认： UTF-8。

`errors` （可选）：如果字符串无法编码，如何处理错误。



encode 函数使用 encoding 指定的编码类型，对 string 进行解码，如果使用 encoding 指定的编码类型无法识别 string 中的编码，则按照 errors 来处理错误。



示例：

```
s = "你好"
b = s.encode(encoding='gbk')
s = b.decode() # b.decode(encoding='utf-8')
```

将 "你好" 转为 gbk 的字节编码，然后尝试使用 utf-8 的编码方式去解码 gbk ，但是 utf-8 无法识别 gbk ，所以就会引发错误。

正确的方法为：

```
s = "你好"
b = s.encode(encoding='gbk')
s = b.decode(encoding='gbk')
```



## 转义字符

字节字符串（`b''`）支持的几种转义序列：

**`\x` 转义序列**：

- 表示一个字节的十六进制值。
- 例如 `\xe4` 表示十六进制值 `e4`。

**`\0` 转义序列**：

- 表示一个空字符（null byte），即字节值 `00`。
- 例如：`b'\0'` 表示一个字节值为 `00` 的字节。

**`\n` 转义序列**：

- 表示换行符（newline character），即字节值 `0A`。
- 例如：`b'\n'` 表示一个换行符。

**`\r` 转义序列**：

- 表示回车符（carriage return），即字节值 `0D`。
- 例如：`b'\r'` 表示一个回车符。

**`\t` 转义序列**：

- 表示制表符（tab character），即字节值 `09`。
- 例如：`b'\t'` 表示一个制表符。

**`\b` 转义序列**：

- 表示退格符（backspace），即字节值 `08`。
- 例如：`b'\b'` 表示一个退格符。

**`\a` 转义序列**：

- 表示警报符（alert or bell），即字节值 `07`。
- 例如：`b'\a'` 表示一个警报符。

**`\f` 转义序列**：

- 表示换页符（form feed），即字节值 `0C`。
- 例如：`b'\f'` 表示一个换页符。

**`\v` 转义序列**：

- 表示垂直制表符（vertical tab），即字节值 `0B`。
- 例如：`b'\v'` 表示一个垂直制表符。

**`\ooo` 转义序列**：

- 表示一个字节的八进制值，其中 `ooo` 是一个最多三位的八进制数。
- 例如：`b'\101'` 表示字节值 `41`（即大写字母 'A'）。



## 进制转换

### int

基础用法

```python
print(int(10))        # 输出: 10
print(int(3.14))      # 输出: 3
print(int(-3.14))     # 输出: -3
print(int("123"))     # 输出: 123
print(int("-123"))    # 输出: -123
```

处理前导零和下划线

```python
print(int("00123"))    # 输出: 123
print(int("1_2_3"))    # 输出: 123
print(int("001_2_3"))  # 输出: 123
```

处理正负号和空格

```python
print(int("+123"))     # 输出: 123
print(int("-123"))     # 输出: -123
print(int("  123  "))  # 输出: 123
```



将**（2 8 16）字符串**转为整形（十进制）。

```python
print(int("101", 2))   # 输出: 5  （二进制）
print(int("ff", 16))   # 输出: 255 （十六进制）
print(int("12", 8))    # 输出: 10  （八进制）
print(int("0b101", 0)) # 输出: 5  （自动检测前缀）
print(int("0x1f", 0))  # 输出: 31 （自动检测前缀）
print(int("0o12", 0))  # 输出: 10 （自动检测前缀）
```



## int to str

Python **hex**() 函数用于将整数转换为**前缀为“0x”**的小写**十六进制**字符串。

```python
i = int("0xff0c23bb",0)
print(hex(i)) # 0xff0c23bb
```

Python **oct**() 函数用于将整数转换为**前缀为“0o”**的小写**八进制**字符串。

```python
i = int("0o261736421",0)
print(oct(i)) # 0o261736421
```

Python **bin**() 函数用于将整数转换为前缀为“0b”的小写**二进制**字符串。

```python
i = int("0b1010010111100011010",0)
print(bin(i)) # 0b1010010111100011010
```

Python **str**() 函数用于将整数转换为**十进制**字符串。

```python
i = int("134241241214",0)
print(str(i)) # 134241241214
```



## int.to_bytes

用途：将**整数**转为**字节数组**。



```
i = 0xffcc
bytes = i.to(4,'little')

等价于 pwntools 中的

bytes = p32(i)
```





length 参数指示，存储这个整数，需要多少字节的内存。对应的是**字节数组**的**元素个数**。



int.to_bytes(length, byteorder, *, signed=False)

返回**表示一个整数**的**字节数组**。

**length** 用于指示 使用多少个字节来存储 整型。

如果整形所占的字节数 大于 length 提供的字节数，则会引发 OverflowError。



**byteorder** 参数确定用于表示整数的字节顺序。

如果 *byteorder* 为 `"big"`，则最高位字节放在字节数组的开头。

如果 *byteorder* 为 `"little"`，则最高位字节放在字节数组的末尾。 



**signed** 参数确定是否使用二的补码来表示整数。 如果 signed 为 False 并且给出的是负整数，则会引发 OverflowError。 signed 的默认值为 False。

示例：

```python
s = "bcefaacf2fc0"
i = int(s,16)

print("i = ", i )
h = i.to_bytes(length=round(len(hex(i)[2:]) / 2),byteorder='big')
print("h = ", h)
# i =  207737548910528
# h =  b'\xbc\xef\xaa\xcf/\xc0'
```

```python
s = "bcefaacf2fc0"
i = int(s,16)

h = i.to_bytes(length=round(len(hex(i)[2:]) / 2),byteorder='big')
print("h = ", h)
# h =  b'\xc0/\xcf\xaa\xef\xbc'
```



## int.from_bytes

作用：将**字节数组**转**为整数**。



```
i = 0xffcc
b = i.to(4,'little')
---

i = int.from_bytes(b,'little')

等价于 pwntools 中的

i = u32(b)
```



classmethod int.from_bytes(bytes, byteorder, *, signed=False)

返回由给**定字节数组**所表示的**整数**。

**bytes** 参数必须为一个 bytes-like object 或是生成字节的可迭代对象。



**byteorder** 参数确定用于表示整数的字节顺序。 

如果 *byteorder* 为 `"big"`，则最高位字节放在字节数组的开头。

如果 *byteorder* 为 `"little"`，则最高位字节放在字节数组的末尾。



**signed** 参数指明是否使用二的补码来表示整数。

示例：

```python
s = "bcefaacf2fc0"
i = int(s,16)

print("i = ", i )
h = i.to_bytes(length=round(len(hex(i)[2:]) / 2),byteorder='big')
print("h = ", h)
i = int.from_bytes(h,byteorder='big')
print("i = ", i )
# i =  207737548910528
# h =  b'\xbc\xef\xaa\xcf/\xc0'
# i =  207737548910528
```

```python
s = "bcefaacf2fc0"
i = int(s,16)

print("i = ", i )
h = i.to_bytes(length=round(len(hex(i)[2:]) / 2),byteorder='big')
print("h = ", h)
i = int.from_bytes(h,byteorder='little')
print("i = ", i )
h = i.to_bytes(length=round(len(hex(i)[2:]) / 2),byteorder='big')
print("h = ", h)

# i =  207737548910528
# h =  b'\xbc\xef\xaa\xcf/\xc0'
# i =  211311580082108
# h =  b'\xc0/\xcf\xaa\xef\xbc'
```



## bytes and bytearray

bytes 是只读的，bytearray 是读写的。

Python 3 的 `bytes` 和 `bytearray` 类都保存字节数组，其中每个字节可以取 0 到 255 之间的值。主要区别在于 `bytes` 对象是*不可变*的，这意味着一旦创建，就无法修改其元素。相比之下，`bytearray` 对象允许您修改其元素。

`bytes` 和 `bytearray` 都提供了用于编码和解码字符串的函数。



bytes 对象可以通过几种不同的方式构造：

```python
>>> bytes(5)
b'\x00\x00\x00\x00\x00'

>>> bytes([116, 117, 118])
b'tuv'

>>> b'tuv'
b'tuv'

>>> bytes('tuv')
TypeError: string argument without an encoding

>>> bytes('tuv', 'utf-8')
b'tuv'

>>> 'tuv'.encode('utf-8')
b'tuv'

>>> 'tuv'.encode('utf-16')
b'\xff\xfet\x00u\x00v\x00'

>>> 'tuv'.encode('utf-16-le')
b't\x00u\x00v\x00'
```

由于 bytes 对象是不可变的，因此尝试更改其元素之一会导致错误：

```python
>>> a = bytes('tuv', 'utf-8')
>>> a
b'tuv'
>>> a[0] = 115
TypeError: 'bytes' object does not support item assignment
```



bytearray 可以通过多种方式构造：

```python
>>> bytearray(5)
bytearray(b'\x00\x00\x00\x00\x00')

>>> bytearray([116, 117, 118])
bytearray(b'tuv')

>>> bytearray('tuv')
TypeError: string argument without an encoding

>>> bytearray('tuv', 'utf-8')
bytearray(b'tuv')

>>> bytearray('tuv', 'utf-16')
bytearray(b'\xff\xfet\x00u\x00v\x00')

>>> bytearray('abc', 'utf-16-le')
bytearray(b't\x00u\x00v\x00')
```

因为 `bytearray` 是*可变*的，所以你可以修改它的元素：

```python
>>> a = bytearray('tuv', 'utf-8')
>>> a
bytearray(b'tuv')
>>> a[0]=115
>>> a
bytearray(b'suv')
```



附加 bytes 和 bytearray

`bytes` 和 `bytearray` 对象可以使用 + 运算符进行连接：

```python
>>> a = bytes(3)
>>> a
b'\x00\x00\x00'

>>> b = bytearray(4)
>>> b
bytearray(b'\x00\x00\x00\x00')

>>> a+b
b'\x00\x00\x00\x00\x00\x00\x00'

>>> b+a
bytearray(b'\x00\x00\x00\x00\x00\x00\x00')
```

请注意，连接的结果采用第一个参数的类型，因此 `a+b` 生成一个 `bytes` 对象，`b+a` 生成一个 `bytearray`。



可以使用 `decode` 函数将 bytes 和 `bytearray` 对象转换为字符串。该函数假定您提供与编码类型相同的解码类型。例如：

```python
>>> a = bytes('tuv', 'utf-8')
>>> a
b'tuv'
>>> a.decode('utf-8')
'tuv'

>>> b = bytearray('tuv', 'utf-16-le')
>>> b
bytearray(b't\x00u\x00v\x00')
>>> b.decode('utf-16-le')
'tuv'
```

