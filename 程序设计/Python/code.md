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