#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   app.py    
@Contact :   851151418@qq.com
@License :   (C)Copyright 2016-2020, iCOMgx's Atai

@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2020-04-11 2:46   Atai      1.0         None
'''
import Key.RSA

if __name__ == '__main__':
    # Key.RSA.CreateRSAKeys()
    text = "1234567890"
    e_text = Key.RSA.RSAPublicKeyEncrypt(text, 'PublicKey.pem')
    print(e_text)
    print('----------------------------------------------------------------')
    d_text = Key.RSA.RSAPrivateKeyDecrypt(e_text, 'PrivateKey.pem')
    print(str(d_text, encoding = "utf8"))