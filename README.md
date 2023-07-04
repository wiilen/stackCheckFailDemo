# iOS 中的栈内存保护： ____stack_chk_fail 和 ARMv8.3 的指针验证机制

## 简介

在 iOS 中，有类错误可能并不常见：____stack_chk_fail。如果引入过 c 相关的代码，并且该代码中执行的时候出现了栈溢出的情况，就有可能在堆栈中出现 ____stack_chk_fail。

从名字上来看，这是栈检查失败的时候抛出的异常。如果我们扩大搜索范围，可以发现各个系统中都有针对这个异常的说明，引申到如栈溢出攻击等场景。那在 iOS 中，这个错误一般代表什么呢？

iOS 中，这个方法和它在其他 c 环境中的作用相似：用于检测返回值是否被修改了。它的基础逻辑如下：在函数开头的位置，分配出一个专门的栈空间，存储一个绝对不会改变的 canary 值，如 pc 寄存器的地址，这个位置一般位于函数和返回值之间的位置；在返回时检查这个值，如果这个值被改变了，说明有意外的地方修改了这个值，于是直接抛出 ____stack_chk_fail。

> 示意图来自 https://nocbtm.github.io/2020/04/28/stack-chk-fail%E7%9B%B8%E5%85%B3%E5%88%A9%E7%94%A8/#%E5%88%A9%E7%94%A8%E6%80%9D%E8%B7%AF

```
 Low Address |                 |
             +-----------------+
     esp =>  | local variables |
             +-----------------+
             |    buf[0-3]     |
             +-----------------+
             |    buf[4-7]     | <= buffer overflow，顺序往下写，导致覆盖了 canary 值
             +-----------------+
             |     canary      |
             +-----------------+
     ebp =>  |     old ebp     |
             +-----------------+
             |   return addr   |
             +-----------------+
             |      args       |
             +-----------------+
High Address |                 |
```

一般来说如果通过栈溢出攻击修改到返回地址 addr，就会把它前面的所有值都修改（通过 index 溢出的方式，往超出分配范围的内存中写入值，所以是会连续写入）。由于不知道 canary 值是什么，修改的时候就无法写入相同的值，从而检测出 canary 被修改了。

> 这里的 EBP 指的是用于恢复返回方法堆栈的指针。

## 内存问题和常见解决办法

我们先来了解一下目前对于内存问题的常见解决方法，这些大家可能都有听说过。

软件安全中，内存问题是一个比较常见的问题。攻击者可以通过修改内存来达到控制程序执行流程的目的。常见的方法包括缓冲区溢出攻击（buffer overflow），通过溢出来写入数据，修改函数的返回地址。目前也有三种常见的防护方式：

1. **将敏感数据和指针放入只读区**：对静态指针效果很好，但对动态指针没有效果。
2. **使用指针前验证**：Control Flow Integrity (CFI) 和 Return Oriented Programming (ROP) 会验证一些跳转和返回地址的属性，来防止问题。
3. **随机化技术**：包括对堆和栈的随机，使地址更难找到；Address Space Layout Randomization (ASLR) 地址空间布局随机化：iOS 4.3 引入的机制，每次启动都会加一个随机的偏移量，函数的调用会带上这个偏移量，更难获取要修改的地址。某些栈防护策略是建立在不可预测性上的，比如上述提到的 ____stack_chk_fail。

这些策略一般需要配合使用，当前的防护策略设计也是建立在多个策略的组合使用上。

## Demo 验证

我们直接跑个 demo 看看检测效果，运行后可以看到 __stack_chk_fail 的堆栈。

https://github.com/wiilen/stackCheckFailDemo

根据使用的 c 函数，实测会插入不同的栈保护方法。这里尝试了几个可能导致 overflow 的 c 函数。

### strcpy、memcpy、sprintf

这些个方法会插入 __xxx_chk 来做校验，比如 __strcpy_chk，逻辑也比较简单，验证 copy 目标的长度，短的话就执行 `__chk_fail_overflow ()`。类似的还有 memcpy、sprintf 函数，都被换为相似的 chk 函数用来保护溢出的情况。

> 以下代码来自苹果的开源代码 Libc 1534.81.1 感兴趣也可以直接阅读源码。
>
> https://github.com/apple-oss-distributions/Libc/releases/tag/Libc-1534.81.1

```
#ifndef UNIFDEF_DRIVERKIT
#if __has_builtin(__builtin___strcpy_chk) || defined(__GNUC__)
#undef strcpy
/* char *strcpy(char *dst, const char *src) */
#define strcpy(dest, ...) \
        __builtin___strcpy_chk (dest, __VA_ARGS__, __darwin_obsz (dest))
#endif

char *
__strcpy_chk (char *restrict dest, char *restrict src, size_t dstlen)
{
  // stpcpy returns a pointer to the \0
  size_t len = stpcpy(dest, src) - dest + 1;

  if (__builtin_expect (dstlen < len, 0))
    __chk_fail_overflow ();

  if (__builtin_expect (__chk_assert_no_overlap, 1))
    __chk_overlap(dest, len, src, len);

  return dest;
}
```

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/c6f609de04b24102bcb6b2172296e1c4~tplv-k3u1fbpfcp-zoom-1.image)

### 未开启 Stack Protection

这里使用 for 循环来检测这个问题，可以看到出现了 EXC_BAD_ACCESS，内存被改坏了。

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/abb1a433973c4c439866c4430e6a1046~tplv-k3u1fbpfcp-zoom-1.image)

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/1c665516661845cba347ea429caf7c4b~tplv-k3u1fbpfcp-zoom-1.image)

往后修改值都为 'a'，这里发现报的错不是 __stack_chk_fail，而是 EXC_BAD_ACCESS，地址则是被 'a' 覆盖了的地址 0x61616161。('a' ascii 码为 0x61)。这里说明这样写实际上没有插入 __stack_chk_fail。

### 开启 Stack Protection

需要在 Build Settings 中加上 `-fstack-protector-all` 来开启。

> 注：由于 Stack Protection 默认只对 vulnerable function 开启，为了展示开启后具体堆栈，这里使用了 -all 参数。
>
> 通过在控制台输入 `clang --help | grep stack-protect`，可以看到相关的类型：
>
> ```
>   -fno-stack-protector      Disable the use of stack protectors
>   -fstack-protector-all     Enable stack protectors for all functions
>   -fstack-protector-strong  Enable stack protectors for some functions vulnerable to stack smashing. Compared to -fstack-protector, this uses a stronger heuristic that includes functions containing arrays of any size (and any type), as well as any calls to alloca or the taking of an address from a local variable
>   -fstack-protector         Enable stack protectors for some functions vulnerable to stack smashing. This uses a loose heuristic which considers functions vulnerable if they contain a char (or 8bit integer) array or constant sized calls to alloca , which are of greater size than ssp-buffer-size (default: 8 bytes). All variable sized calls to alloca are considered vulnerable. A function with a stack protector has a guard value added to the stack frame that is checked on function exit. The guard value must be positioned in the stack frame such that a buffer overflow from a vulnerable variable will overwrite the guard value before overwriting the function's return address. The reference stack guard value is stored in a global variable.
> ```

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/c7642f5d1abe4ea387048cc9dfcb51fd~tplv-k3u1fbpfcp-zoom-1.image)

开启之后就会发现，堆栈中出现了 __stack_chk_fail，说明溢出的问题被检测到了。

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/2288059563ca4fb0a23e3d91d1ffa580~tplv-k3u1fbpfcp-zoom-1.image)

## 常见栈保护下插入的汇编

在看过上面的 demo 之后，我们可以更进一步，看看编译器是如何插入 __stack_chk_fail 的。

> 注：按照之前在项目中遇到的情况，stack protection 默认会针对 vulnerable function 开启，行为比较符合 `-fstack-protector` 的行为，所以如果没有手动填入其他的 stack-protector 参数，也有可能会看到被保护的栈。
>
> 苹果在 WWDC 2018 中提到，Xcode 会默认开启 stack protect https://devstreaming-cdn.apple.com/videos/wwdc/2018/409t8zw7rumablsh/409/409_whats_new_in_llvm.pdf ，视频备份 https://wwdctogether.com/wwdc2018/409 ，也就是至少在 Xcode 9 开始就有了。中文解析可以参考 https://iweiyun.github.io/2018/10/15/What-New-in%20LLVM-WWDC2018/ 。
>
> ![现在这里的 strcpy 已经被换成了 __strcpy_chk，不会走到 canary 的逻辑](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/b0afdacd8b5c4c6da432f8eb85729507~tplv-k3u1fbpfcp-zoom-1.image)
>
> ![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/2239e748f833457fb0b6f2a87be728f8~tplv-k3u1fbpfcp-zoom-1.image)
>
> Swift 本身是一门比较安全的语言，但也有 case 可能导致内存问题。这里有相关的讨论：https://forums.swift.org/t/stack-protectors-in-swift/60163 ，比如 unsafeMutablePointer。
>
> 补充：具体编译器用哪种校验方法都可以，基本都是栈上额外放置一个不应该被写的数据，然后函数返回前检测一下。看 Clang 实现是，往 x19 寄存器，和栈上校验用变量存放了相同值，退出前校验值相同。

这里截取了高通文档中描述的，常规情况下栈保护添加的代码：

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/53c2c31411bb4c90949a47bc38b65309~tplv-k3u1fbpfcp-zoom-1.image)

相比于左边的代码，这里在函数的开始位置，这里多分配了 0x10 的空间，用来做最后标红的三个指令：

1. 把 pc 寄存器的页地址存入 x3。注意这里用的是 ADRP，不是 LDR，所以实际上没有取出 pc 存的地址，而是只取出了页地址，这样可以确保这个值是相对不容易变化的。
2. 这里往 x4 写入了 x3 地址加上 #SSP，这样往 x4 里存入的就是一个实际的地址。
3. 然后把 x4 存到 sp + 0x38 的位置，也就是之前多分配一部分的空间。

然后在函数返回之前：

4. 把 x3 + #SSP 的地址写入 x1，然后把 sp + 0x38 的地址写入 x2，对比他们的值。
5. 如果发生了栈溢出攻击，sp + 0x38 的位置会先被写入替换成别的值。
6. 这样如果发现 x1 和 x2 不同，就可以说明发生了栈溢出。

## ARMv8.3 的优化

ARMv8.3 引入了一个指针验证机制（Pointer Authentication mechanism），用于保护关键位置的指针不被修改，防止通过修改返回位置的指针来控制程序的执行流程。相比于常规的栈保护，这个机制把汇编代码缩减为两行，分别是函数开始时插入的指令和函数结束时插入的指令，简化了整个流程。

> arm64e 基于的是 ARMv8.3，它和 arm64 最大的区别就是多了指针认证。
>
> 补充：在 arm64 到 arm64e 后，多了这个 e 之后， stack chk failed 就没有意义了，相当于 CPU 内置支持 check stack failed. 比如现在arm64e系统(设备大于 iPhoneX 都是 arm64e)内的所有函数基本都默认开启 PAC 校验。但是因为我们 App，上传到 App Store 只支持 arm64 格式的，所以目前还是在用 stack chk failed。

### 指针认证

指针认证背后的基本思想是，64位架构中实际的使用的地址小于64位。指针值中有未使用的位，我们可以使用这些位来放置指针认证码（PAC）。我们可以在将指针写入内存之前将PAC插入到每个要保护的指针中，并在使用之前验证其完整性。攻击者想要修改受保护的指针，必须找到/猜测正确的PAC才能控制程序流。

### 相关指令

对于指针认证，需要两个主要操作：计算并添加 PAC，以及验证 PAC 并恢复指针值。这些分别由 PAC *和 AUT *一组指令处理。如果在 AUT 指令期间验证失败，则处理器将 PAC 替换为特定模式，使得指针值成为非法地址。当引用无效指针时，通过非法地址异常进行实际错误检测。这种设计将错误处理与指令分离，并消除了使用其他指令进行错误处理的需要。通过检查 AUT 指令发出错误信号的模式，异常处理程序可以区分「非法地址异常」和「身份验证失败」。

生成 PAC 使用的是 QARMA 算法，它需要两个参数：指针和上下文。输出的是一个裁剪过的段以便放到指针中，通常 PACGA 指令会生成 32 位的 PAC，但是要放到指针中时会被缩短到 21 位。

虚拟内存地址一般存放在 32 位和 52 位之间，如果开启了 tagged address，PAC 就会放在 3-23 位之间，关闭时会放在 11-31 位之间。

## 指针认证下插入的汇编

![](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/fe52d4bc6cbb4744ab6c42bbb7fabe25~tplv-k3u1fbpfcp-zoom-1.image)

实际上是把函数入口的指令和返回前的指令分别优化成一条了。

以下解释来自 ChatGPT，经过了一些修改使得它更通顺。

* * *

1. `PACIASP` 和 `AUTIASP` 是 ARMv8.3-A 架构中引入的两条指令，它们是指针认证机制的一部分。
2. `PACIASP` 代表 “使用密钥 A 和 SP 对指令地址生成 PAC”。此指令计算并插入一个 PAC，使用存储在链接寄存器 lr（`x30`）中的指令地址作为输入指针，使用栈指针（`SP`）作为上下文，并使用密钥 A 进行认证。
3. `AUTIASP` 代表 “使用密钥 A 和 SP 对指令地址进行认证”。此指令对存储在链接寄存器（`x30`）中的指令地址进行验证，使用栈指针（`SP`）作为上下文，并使用密钥 A 进行认证。如果认证失败，该指令会将 PAC 替换为特定的值，使指针值成为非法地址。
4. 这些指令用于防止基于返回的编程（ROP）攻击，确保存储在堆栈上的返回地址未被攻击者修改。在从函数返回之前，使用 `AUTIASP` 指令对存储在堆栈上的返回地址进行认证。如果认证失败，则表明返回地址已被修改，程序可以采取适当措施，例如终止进程或调用堆栈检查失败处理程序。

* * *

如果在`AUTIASP`验证时发现PAC错误，就会把地址替换成特定的模式，导致整个地址成为非法地址。

## 总结

无论是 ____stack_chk_fail 还是 PAC，都是对现有内存问题的一种保护。相比于前者插入 canary 的方案，PAC 明显会更节省执行时间，指令条数从 7 条缩短到 2 条。不过日常开发中我们更经常遇到的还是前者，知道了这个错误代表什么之后，就更容易查找问题了。

对于 c 相关内存问题，栈内存保护能做到的也比较有限，主要保护的是关键指针不被修改。对于其他类型的内存问题，比如 double free、use after free 等，还是需要 ASan 来帮助定位。

## 参考文档

1.  [Pointer Authentication on ARMv8.3](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/pointer-auth-v7.pdf)
1.  https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/
1.  https://developer.arm.com/documentation/dui0801/k/A64-General-Instructions/AUTIA--AUTIZA--AUTIA1716--AUTIASP--AUTIAZ?lang=en
1.  https://developer.arm.com/documentation/100067/0612/armclang-Command-line-Options/-fstack-protector---fstack-protector-all---fstack-protector-strong---fno-stack-protector
1.  WWDC 2018 what's new in llvm PDF https://devstreaming-cdn.apple.com/videos/wwdc/2018/409t8zw7rumablsh/409/409_whats_new_in_llvm.pdf
1.  WWDC 2018 what's new in llvm 视频 https://wwdctogether.com/wwdc2018/409
1.  微云对上文中 WWDC session 的解析 https://iweiyun.github.io/2018/10/15/What-New-in%20LLVM-WWDC2018/
