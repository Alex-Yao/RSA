# -*- coding: utf-8 -*-
import logging
import sys
import random
import time
from hashlib import sha256


def coprime(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


# Euclid's extended algorithm for finding the multiplicative inverse of two numbers
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

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

def Prime_test(number):  # 进行素数检测Miller-Robin算法，判别依据a^(n-1)=1(modn)，则可认为n是素数
    s = 6  # 测试的次数为n=0.5*log2(1/e)向上取整
    for i in range(s):
        a = random.randrange(2, number - 1)
        if pow(a, number - 1, number) != 1:  # a^bumber-1=1(number)
            return 0
    return 1

def generate_keypair(p, q):
    if not (Prime_test(p) and Prime_test(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')

    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = coprime(e, phi)

    while g != 1:
        e = random.randrange(1, phi)
        g = coprime(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(privatek, plaintext):
    # Unpack the key into it's components
    key, n = privatek

    # Convert each letter in the plaintext to numbers based on the character using a^b mod m

    numberRepr = [ord(char) for char in plaintext]
    print("加密序列表示为: ", numberRepr)
    cipher = [pow(ord(char), key, n) for char in plaintext]

    # Return the array of bytes
    return cipher


def decrypt(publick, ciphertext):
    # Unpack the key into its components
    key, n = publick

    # Generate the plaintext based on the ciphertext and key using a^b mod m
    numberRepr = [pow(char, key, n) for char in ciphertext]
    plain = [chr(pow(char, key, n)) for char in ciphertext]

    print("解密序列表示为: ", numberRepr)

    return ''.join(plain)


def hashFunction(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed


def verify(receivedHashed, message):
    ourHashed = hashFunction(message)
    if receivedHashed == ourHashed:
        print("检验成功: ", )
        print(receivedHashed, " = ", ourHashed)
    else:

        print("检验失败：")
        print(receivedHashed, " != ", ourHashed)


def main():

    prime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    message = input("输入文本: ")

    stdout_backup=sys.stdout
    log_file = open("log.txt", "a")
    sys.stdout = log_file
    print("明文：",message)
    print('')

    # 产生素数p
    print('-----产生素数-----')
    p = Creat_p_q(prime)
    print('素数p：', end='')
    print(p)
    # 产生素数q
    q = Creat_p_q(prime)
    while (p == q):
        q = Creat_p_q(prime)
    print('素数q：', end='')
    print(q)

    public, private = generate_keypair(p, q)

    print("公钥为：", public, " 私钥为：", private)
    print("")

    print("-----加密、解密操作-----")
    print("公钥加密：", public, " . . .")
    encrypt_c=encrypt(public,message)
    print("加密结果：")
    print("".join(map(lambda x: str(x),encrypt_c)))

    print("")
    print("私钥解密：", private, " . . .")
    decrypted_c = decrypt(private, encrypt_c)
    print("解密结果：",end='')
    print(decrypted_c)
    print("时间戳：",end='')
    print(int(time.time() * 1000))

    print("")
    print("-----数字签名操作-----")
    #Hash函数
    hashed = hashFunction(message)

    print("私钥加密：", private, " . . .")
    encrypted_msg = encrypt(private, hashed)
    print("加密结果：")
    print(''.join(map(lambda x: str(x), encrypted_msg)))

    print("")
    print("公钥解密：", public, " . . .")

    decrypted_msg = decrypt(public, encrypted_msg)
    print("解密结果：")
    print(decrypted_msg)
    print("时间戳：",end='')
    print(int(time.time() * 1000))

    print("")
    print("正在进行检验. . .")
    verify(decrypted_msg, message)
    print('')

    log_file.close()
    sys.stdout = stdout_backup

if __name__=="__main__":
    main()