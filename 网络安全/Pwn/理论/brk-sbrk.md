# brk, sbrk

brk, sbrk - 改变数据段大小（.data）



## 库

标准C库 (libc, -lc)



## 用法

```
#include <unistd.h>
int brk(void *addr);
void *sbrk(intptr_t increment);
```



**特性测试宏要求（针对glibc，参见 feature_test_macros(7)）:**

**brk**(), **sbrk**():

```
    Since glibc 2.19:

        _DEFAULT_SOURCE

            || ((_XOPEN_SOURCE >= 500) &&

                ! (_POSIX_C_SOURCE >= 200112L))

    From glibc 2.12 to glibc 2.19:

        _BSD_SOURCE || _SVID_SOURCE

            || ((_XOPEN_SOURCE >= 500) &&

                ! (_POSIX_C_SOURCE >= 200112L))

    Before glibc 2.12:

        _BSD_SOURCE || _SVID_SOURCE || _XOPEN_SOURCE >= 500
```

- 自glibc 2.19以来:
    - _DEFAULT_SOURCE
    - 或者 ((_XOPEN_SOURCE >= 500) 并且 !(_POSIX_C_SOURCE >= 200112L))
- 从glibc 2.12到glibc 2.19:
    - _BSD_SOURCE || _SVID_SOURCE
    - 或者 ((_XOPEN_SOURCE >= 500) 并且 !(_POSIX_C_SOURCE >= 200112L))
- 在glibc 2.12之前:
    - _BSD_SOURCE || _SVID_SOURCE || _XOPEN_SOURCE >= 500



## 描述

`brk()` 和 `sbrk()` 用于改变程序断点的位置，这定义了进程数据段的结束（即，程序断点是未初始化数据段之后的第一个位置）。增加程序断点的效果是为进程分配内存；减少断点则会释放内存。

`brk()` 将数据段的末尾设置为由 `addr` 指定的值，当该值合理、系统有足够的内存并且进程不超过其最大数据大小（参见 setrlimit(2)）时。

`sbrk()` 通过 **`increment` （有符号）**字节来**增加（或减少）**程序的数据空间。使用 `sbrk()` 并将 `increment` 设为 0 可以用来查找当前的程序断点位置。



## 返回值

成功时，`brk()` 返回 0。失败时，返回 -1，并将 `errno` 设置为 ENOMEM。

成功时，`sbrk()` 返回之前的程序断点。（如果断点被增加，则此值是指向新分配内存起始位置的指针）。失败时，返回 (void*)-1，并将 `errno` 设置为 ENOMEM。



## 标准

无。



## 历史

4.3BSD; SUSv1, 在 SUSv2 中标记为 LEGACY，在 POSIX.1-2001 中移除。



## 注意事项

避免使用 `brk()` 和 `sbrk()`：`malloc(3)` 内存分配包是分配内存的可移植且方便的方式。

不同系统对 `sbrk()` 的参数类型有不同的定义。常见的有 int, ssize_t, ptrdiff_t, intptr_t。



## C库/内核差异

上面描述的 `brk()` 的返回值是由 glibc 包装函数为 Linux 的 `brk()` 系统调用提供的行为。（在大多数其他实现中，`brk()` 的返回值相同；这个返回值也在 SUSv2 中指定。）然而，实际的 Linux 系统调用在成功时返回新的程序断点。失败时，系统调用返回当前断点。glibc 包装函数做了一些工作（例如，检查新的断点是否小于 `addr`），以提供上述的 0 和 -1 的返回值。

在 Linux 上，`sbrk()` 是一个使用 `brk()` 系统调用的库函数，并进行一些内部记录以便它可以返回旧的断点值。



## 参考

execve(2), getrlimit(2), end(3), malloc(3)