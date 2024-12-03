# pthread.h

## 概念介绍

**单线程**与**多线程执行**的可视化对比

**单线程执行**

```c
//              单线程执行
//
//          |   int x;
//          |   x = 20;
//          |   int y;
//  Time    |   y = 50;
//          |   int sum;
//          |   sum = x + y;
//          ↓
```



**多线程执行（并行执行）**

```C
//              多线程执行 
//
//          |   int x;                 |  int a;
//          |   x = 20;                |  a = 3;
//          |   int y;                 |  int b;
//  Time    |   y = 50;                |  b = 5;
//          |   int sum;               |  int product;
//          |   sum = x + y;           |  product = a * b;
//          ↓                          ↓
//
//          Parallel Execution 
```



**多线程执行（并发但非并行执行）**

```C
//              多线程执行 
//
//          |   int x;                 |  
//          |                          |  int a;
//          |                          |  a = 3;
//          |   x = 20;                |  
//          |   int y;                 |   
//          |                          |  int b;
//  Time    |   y = 50;                |  
//          |                          |  b = 5;
//          |                          |  int product;
//          |   int sum;               |  
//          |   sum = x + y;           |  
//          |                          |  product = a * b;
//          ↓                          ↓
//
//          并行执行 
```



**并行执行 (Parallel Execution)**

1. **硬件支持**：并行执行依赖于多核或多处理器的硬件架构。如果计算机有多个CPU核心，那么每个核心可以同时执行一个线程，这意味着多个线程可以在真正的同一时间运行，从而提高程序的执行速度。
2. **性能提升**：当任务是计算密集型并且可以被分割成独立的子任务时，并行执行能够显著减少总的执行时间。例如，在图像处理、科学计算等领域，数据可以被分割为多个部分，每个部分由不同的线程并行处理。
3. **资源消耗**：并行执行可能会导致更高的资源消耗，因为每个线程都需要自己的执行上下文（如寄存器状态、栈等）。此外，更多的线程可能意味着需要更多的内存和更复杂的同步机制来管理线程间的通信。



**非并行执行 (Non-Parallel or Concurrent Execution)**

1. **单核环境**：在单核处理器上，即使创建了多个线程，实际上并不能真正同时执行。操作系统会使用时间片轮转的方式快速切换各个线程的执行，给用户造成一种所有线程都在同时运行的假象。这种情况下，线程是在交替执行，而不是并行执行。
2. **I/O密集型任务**：对于I/O密集型任务（如网络请求、文件读写等），非并行执行仍然可以带来好处。因为当一个线程等待I/O操作完成时，其他线程可以继续执行，从而提高了系统的响应性和效率。
3. **复杂度较低**：相比于并行执行，非并行执行通常较为简单，因为它不需要处理那么多的线程同步问题，也不会引发由于多个线程真正同时访问共享资源而产生的竞态条件（race condition）。



## pthread_create

pthread_create — 创建一个新线程



### 库

POSIX 线程库（libpthread、-lpthread）



### 用法

```C
#include <pthread.h>
int pthread_create(pthread_t *restrict thread,
                   const pthread_attr_t *restrict attr,
                   void *(*start_routine)(void *),
                   void *restrict arg);
```



### 描述

`pthread_create()` 函数在调用进程内启动一个新线程。新线程通过调用 `start_routine()` 开始执行；`arg` 作为 `start_routine()` 的唯一参数传递。

新线程可以通过以下方式终止：

- 它调用 `pthread_exit(3)`，并指定一个退出状态值，该值可以被同一进程中调用 `pthread_join(3)` 的另一个线程获取。
- 它从 `start_routine()` 返回。这相当于以返回语句中提供的值调用 `pthread_exit(3)`。
- 它被取消（参见 `pthread_cancel(3)`）。
- 进程中的任何线程调用 `exit(3)`，或者主线程从 `main()` 返回。这会导致进程中的所有线程终止。

`attr` 参数指向一个 `pthread_attr_t` 结构，其内容在创建线程时用于确定新线程的属性；此结构使用 `pthread_attr_init(3)` 和相关函数初始化。如果 `attr` 为 NULL，则线程将以默认属性创建。

在成功调用 `pthread_create()` 之前，它会将新线程的 ID 存储在 `thread` 指向的缓冲区中；这个标识符用于在后续调用其他 POSIX 线程函数时引用该线程。

新线程继承了创建线程的信号掩码副本（`pthread_sigmask(3)`）。新线程的挂起信号集为空（`sigpending(2)`）。新线程不会继承创建线程的备用信号栈（`sigaltstack(2)`）。

新线程继承了调用线程的浮点环境（`fenv(3)`）。

新线程的 CPU 时间钟的初始值为 0（参见 `pthread_getcpuclockid(3)`）。

Linux 特定细节 新线程继承了调用线程的能力集（`capabilities(7)`）和 CPU 亲和性掩码（`sched_setaffinity(2)`）的副本。



### 返回值

成功时，`pthread_create()` 返回 0；错误时，它返回一个错误编号，并且 `*thread` 的内容未定义。



### 错误

- `EAGAIN`: 资源不足，无法创建另一个线程。
- `EAGAIN`: 遇到了系统强加的线程数量限制。可能触发此错误的限制包括：每个真实用户 ID 的进程和线程数量软资源限制（通过 `setrlimit(2)` 设置），即 `RLIMIT_NPROC`；内核对整个系统范围内进程和线程数量的限制，`/proc/sys/kernel/threads-max`（参见 `proc(5)`）；或最大 PID 数量，`/proc/sys/kernel/pid_max`（参见 `proc(5)`）。
- `EINVAL`: `attr` 中有无效设置。
- `EPERM`: 没有权限设置 `attr` 中指定的调度策略和参数。



### 属性

有关本节所用术语的解释，请参阅 `attributes(7)`。

| 接口               | 属性       | 值      |
| ------------------ | ---------- | ------- |
| `pthread_create()` | 线程安全性 | MT-Safe |



### 标准

POSIX.1-2001, POSIX.1-2008.



### 注意

请参阅 `pthread_self(3)` 以了解由 `pthread_create()` 在 `*thread` 中返回的线程 ID 的更多信息。除非使用实时调度策略，否则在调用 `pthread_create()` 后，不确定哪个线程——调用者或新线程——将首先执行。

线程可以是可连接的（joinable）或分离的（detached）。如果线程是可连接的，那么另一个线程可以调用 `pthread_join(3)` 来等待该线程终止并获取其退出状态。只有当一个已终止的可连接线程被连接后，它的资源才会释放回系统。当一个分离的线程终止时，它的资源会自动释放回系统：不可能连接到该线程以获取其退出状态。默认情况下，新线程是以可连接状态创建的，除非 `attr` 被设置为以分离状态创建线程（使用 `pthread_attr_setdetachstate(3)`）。

在 NPTL 线程实现中，如果程序启动时 `RLIMIT_STACK` 软资源限制不是“无限制”，则它决定了新线程的默认堆栈大小。使用 `pthread_attr_setstacksize(3)`，可以在创建线程时显式设置 `attr` 参数中的堆栈大小属性，以获得不同于默认值的堆栈大小。如果 `RLIMIT_STACK` 资源限制设置为“无限制”，则根据架构使用特定的堆栈大小。以下是几种架构的默认堆栈大小：

| 架构     | 默认堆栈大小 |
| -------- | ------------ |
| i386     | 2 MB         |
| IA-64    | 32 MB        |
| PowerPC  | 4 MB         |
| S/390    | 2 MB         |
| Sparc-32 | 2 MB         |
| Sparc-64 | 4 MB         |
| x86_64   | 2 MB         |



### 缺陷

在废弃的 LinuxThreads 实现中，进程中的每个线程都有不同的进程 ID。这违反了 POSIX 线程规范，并且是许多不符合标准的行为的根源；参见 `pthreads(7)`。



### 示例

**并发执行示例**

```C
//              多线程执行 
//
//          |                             pthread
//          |
//          |   sum = x + y;           
//          |   pthread_create --------   function()
//          |   ...                    |  int a = 5;
//          |   printf("%d", sum);     |  int b = 3;
//  Time    |   ...                    |  int result = x + y;
//          |   pthread_join   --------↓
//          |   ...       | 
//          |   ...       |   
//          ↓          执行在此暂停，直到线程完成
//
//          并行执行 
```



**简单并发示例**

```C
#include <stdio.h>
#include <pthread.h>

void *computation();

int main()
{
  pthread_t thread1;

  pthread_create(&thread1, NULL, computation, NULL);

  pthread_join(thread1, NULL);


  return 0;
}

void *computation()
{
  printf("Computation\n");
  return NULL;
}
```



**传入参数并发示例**

```C
#include <stdio.h>
#include <pthread.h>

void *computation(void * num);

int main()
{
  pthread_t thread1;
  int num = 10;

  pthread_create(&thread1, NULL, computation, (void*) &num);

  pthread_join(thread1, NULL);


  return 0;
}

void *computation(void * num)
{
  int * p = (int*) num;
  printf("Value = %d\n",*p);
  return NULL;
}
```



**两个（子）线程并发示例**

```C
#include <stdio.h>
#include <pthread.h>

void *computation();

int main()
{
  pthread_t thread1;
  pthread_t thread2;
  
  pthread_create(&thread1, NULL, computation, NULL);
  pthread_create(&thread2, NULL, computation, NULL);
  
  pthread_join(thread1, NULL);
  pthread_join(thread2, NULL);

  return 0;
}

void *computation()
{
  long sum = 0;
  for (long i = 0; i < 1000000000; i++)
    sum += i;

  return NULL;
}
```

执行时间：

```
time ./thred 

real	0m0.708s
user	0m1.405s
sys	0m0.002s
```



单线程：

```C
// ...

int main()
{
  computation(); // one
  computation(); // two
  return 0;
}

void *computation()
{
	// ...
}
```

执行时间：

```
time ./thred 

real	0m1.409s
user	0m1.405s
sys	0m0.002s
```



## pthread_join

### 名称

`pthread_join` - 与一个已终止的线程连接



### 函数库

POSIX 线程库 (libpthread, -lpthread)



### 语法

```C
#include <pthread.h>
int pthread_join(pthread_t thread, void **retval);
```



### 描述

`pthread_join()` 函数会等待由 `thread` 指定的线程终止。如果该线程已经终止，则 `pthread_join()` 会立即返回。`thread` 所指定的线程必须是可连接的（joinable）。

如果 `retval` 不是 `NULL`，那么 `pthread_join()` 会将目标线程的退出状态（即目标线程传递给 `pthread_exit(3)` 的值）复制到 `retval` 指向的位置。如果目标线程被取消，则会在 `retval` 指向的位置放置 `PTHREAD_CANCELED`。

如果多个线程同时尝试与同一个线程连接，结果是未定义的。如果调用 `pthread_join()` 的线程被取消，那么目标线程将保持可连接状态（即它不会被分离）。



### 返回值

成功时，`pthread_join()` 返回 0；出错时，它返回一个错误编号。



### 错误

- `EDEADLK`: 检测到了死锁（例如，两个线程试图互相连接）；或者 `thread` 指定了调用线程本身。
- `EINVAL`: `thread` 不是一个可连接的线程。
- `EINVAL`: 另一个线程已经在等待与这个线程连接。
- `ESRCH`: 没有找到 ID 为 `thread` 的线程。



### 属性

有关本节中使用的术语解释，请参阅 `attributes(7)`。

| 接口             | 属性       | 值      |
| ---------------- | ---------- | ------- |
| `pthread_join()` | 线程安全性 | MT-Safe |



### 标准

POSIX.1-2001, POSIX.1-2008.



### 注意事项

成功调用 `pthread_join()` 后，调用者可以确保目标线程已经终止。调用者可以选择在目标线程终止后进行任何必要的清理工作（例如，释放分配给目标线程的内存或其他资源）。

与之前已经被连接过的线程再次连接会导致未定义行为。

未能与一个可连接的线程（即不是分离的线程）连接会产生“僵尸线程”。应避免这种情况，因为每个僵尸线程都会消耗一些系统资源，并且当积累足够多的僵尸线程时，将不再可能创建新的线程（或进程）。

没有 `pthreads` 类似于 `waitpid(-1, &status, 0)` 的功能，也就是说，“与任意已终止的线程连接”。如果你认为你需要这种功能，你可能需要重新考虑你的应用程序设计。

进程中的所有线程都是对等的：任何线程都可以与其他任何线程连接。



### 示例

**多个线程并发执行**

```C
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

struct arg {
    size_t start;
    size_t end;
};

void * sub_thread(void * p);

int main(void) {

    const size_t NUM   = 10;   // thread number

    const size_t sum_num = 1000; // 1 + 2 + 3 + ... + sum_num
    const size_t const * array = (size_t[]){0,100,200,300,400,500,600,700,800,900,1000};
    struct arg arg[NUM];

    pthread_t th_array[NUM]; 

    for(size_t i = 0;i < NUM;i++) {
        arg[i] = (struct arg){.start = array[i] + 1,.end = array[i + 1]};
        pthread_create(th_array + i,NULL,sub_thread,(void*)(arg + i));
    }

    size_t sum = 0;
    for(int i = 0;i < NUM;i++) {
        void * th_rn = NULL;
        pthread_join(th_array[i],&th_rn);

        if(th_rn == NULL)
            exit(1);

        sum += *((size_t*)th_rn); 
        free(th_rn);
    }

    printf("1 + 2 + ... + %ld + %ld = %ld\n",sum_num - 1,sum_num,sum);

    return 0;
}

void * sub_thread(void * p) {

    struct arg * arg = p;

    size_t * sum = (size_t*) malloc(sizeof(size_t));
    size_t start = arg->start;
    size_t   end = arg->end;

    *sum = 0;
    while(start <= end) {
        *sum += start;
        start++;
    }

    return (void*)(sum);
}
```

