# -*- coding: utf-8 -*-
import random
from hashlib import sha256


def Prime_test(number):  # 进行素数检测Miller-Robin算法，判别依据a^(n-1)=1(modn)，则可认为n是素数
    s = 6  # 测试的次数为n=0.5*log2(1/e)向上取整
    for i in range(s):
        a = random.randrange(2, number - 1)
        if pow(a, number - 1, number) != 1:  # a^bumber-1=1(number)
            return 0
    return 1


def Creat_p_q(prime):
    while (1):
        temp = random.randrange(2 ** 20, 2 ** 25)
        # 用100内的素数进行素性探测，排除大部分非素数
        for i in range(len(prime)):
            if temp % prime[i] == 0:
                break
        if i < len(prime) - 1:
            continue
        # 进入Miller-Robin素性探测算法
        if (Prime_test(temp) != 1):
            continue
        else:
            return temp


# 判别两个数是否互质
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


# 得到两个大素数p、q后，产生公钥对和私钥对
def Creat_Key(p, q):
    n = p * q
    m = (p - 1) * (q - 1)
    while (1):
        temp = random.randrange(m)
        if gcd(m, temp) == 1:
            e = temp
            break

        # 欧几里得求逆元法：若a x=1 mod f ，则称a关于摸f的乘法逆元为x
    x1 = 1;x2 = 0;x3 = m
    y1 = 0; y2 = 1; y3 = e
    while y3 != 1:
        if y3 == 0:
            return 0  # e没有逆元
        q = int(x3 / y3)  # 整除
        t1 = x1 - q * y1;t2 = x2 - q * y2; t3 = x3 - q * y3
        x1 = y1;x2 = y2;x3 = y3
        y1 = t1;y2 = t2;y3 = t3
    d = y2 % m
    return [int(n), int(e), int(n), int(d)]


class En_De_crypt:
    text = ''

    def __init__(self, text):
        self.text = text

    def Encrypt(self, key):
        ctext = []
        for i in self.text:
            c = pow(ord(i), key[1], (key[0]))
            ctext.append(c)
        return ctext

    def Decrypt(self, ctext, key):
        mtext = []
        for i in ctext:
            m = pow(i, key[3], (key[2]))
            mtext.append(m)
        return mtext


def hashFunction(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed


def verify(receivedHashed, message):
    vHashed = hashFunction(message)
    if receivedHashed == vHashed:
        print("认证成功")
        print(receivedHashed, "=", vHashed)
    else:
        print("认证失败")
        print(receivedHashed, "!=", vHashed)


def main():  # 100以内的素数表
    prime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    # 产生素数p
    print('产生素数：')
    p = Creat_p_q(prime)
    print('素数p：', end='')
    print(p)
    # 产生素数q
    q = Creat_p_q(prime)
    while (p == q):
        q = Creat_p_q(prime)
    print('素数q：', end='')
    print(q)

    # 产生公钥对和私钥对
    key = Creat_Key(p, q)
    print('公钥和私钥元组[n,e,n,d]:', end='')
    print(key)

    # 输入待加密文本
    text = input('输入待加密文本：')
    class1 = En_De_crypt(text)

    # 进行加密ctext是已加密文本
    ctext = class1.Encrypt(key)
    print('加密后的文本数字编码：', end='')
    print(ctext)

    # 进行解密mtext是解密的文本
    mtext = class1.Decrypt(ctext, key)
    print('解密后的文本数字编码：', end='')
    print(mtext)
    str = ''
    for i in range(0, len(mtext)):
        str = str + chr(mtext[i])
    print('解密后的文本：%s' % str)

    print("--签名认证--")
    message = text
    print("待签名文本：", text)
    hashed = hashFunction(message)
    print(hashed)

    encrypted_msg=[]
    decrypted_msg=[]

    class1 = En_De_crypt(hashed)
    encrypted_msg = class1.Encrypt(key)
    print("签名后的文本：",encrypted_msg)
    #print(''.join(map(lambda x: str, encrypted_msg)))
    decrypted_msg = class1.Decrypt(key, encrypted_msg)

    print("解签后文本: %s" %decrypted_msg)

    print("正在进行签名验证。。。")
    # print(decrypted_msg)
    verify(decrypted_msg, message)


if __name__ == '__main__':
    main()
