#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   RSA.py    
@Contact :   851151418@qq.com
@License :   (C)Copyright 2016-2020, iCOMgx's Atai

@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2020-04-11 2:43   Atai      1.0         None
'''

import Crypto.PublicKey.RSA
import Crypto.Cipher.PKCS1_v1_5
import Crypto.Random
import Crypto.Signature.PKCS1_v1_5
import Crypto.Hash
import base64

# 生成一对RSA密钥
def CreateRSAKeys():
    x = Crypto.PublicKey.RSA.generate(3072)
    a = x.exportKey("PEM")  # 生成私钥
    b = x.publickey().exportKey()  # 生成公钥
    with open("PrivateKey.pem", "wb") as x:
        x.write(a)
    with open("PublicKey.pem", "wb") as x:
        x.write(b)


# 使用公钥加密
def RSAPublicKeyEncrypt(data, publicKey):
    with open(publicKey, "rb") as x:
        b = x.read()
        cipher_public = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(b))
        text = data.encode(encoding="utf-8")
        cipher_text = cipher_public.encrypt(text)  # 使用公钥进行加密
        return base64.b64encode(cipher_text)


# 使用私钥解密
def RSAPrivateKeyDecrypt(data, privateKey):
    with open(privateKey, "rb") as x:
        a = x.read()
        # 如果私钥有密码 则使用相应密码 Crypto.PublicKey.RSA.importKey(a, password)
        cipher_private = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.importKey(a))
        cipher_text = base64.b64decode(data)
        text = cipher_private.decrypt(cipher_text, Crypto.Random.new().read)  # 使用私钥进行解密
        return str(text, encoding="utf8")


# 使用私钥进行SHA256签名
def RSAPrivateKeySignature(data, privateKey):
    with open(privateKey, "rb") as x:
        c = x.read()
        c_rsa = Crypto.PublicKey.RSA.importKey(c)
        signer = Crypto.Signature.PKCS1_v1_5.new(c_rsa)
        msg_hash = Crypto.Hash.SHA256.new()
        msg_hash.update(data)
        sign = signer.sign(msg_hash)  # 使用私钥进行'sha256'签名
        return sign


# 使用公钥进行验签
def RSAPublicKeyCheckSignature(sign, text, publicKey):
    with open(publicKey, "rb") as x:
        d = x.read()
        d_rsa = Crypto.PublicKey.RSA.importKey(d)
        verifer = Crypto.Signature.PKCS1_v1_5.new(d_rsa)
        msg_hash = Crypto.Hash.SHA256.new()
        msg_hash.update(text)
        verify = verifer.verify(msg_hash, sign)  # 使用公钥验证签名
        return verify
