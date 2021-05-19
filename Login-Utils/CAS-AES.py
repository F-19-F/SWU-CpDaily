# -*- coding: utf-8 -*-
import requests
from datetime import datetime, timedelta, timezone
from pyDes import des, CBC, PAD_PKCS5
import pyaes#用于aes加密
import urllib.parse as up
from aip import AipOcr
import random
import base64
import sys
import json
import os
import re
import time
import traceback
MAX_Captcha_Times=20
class Util: #统一的类
    logs='CAS-AES-Login'
    OCRclient = None
    @staticmethod
    def GetDate(Mod='%Y-%m-%d %H:%M:%S',offset=0):
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8,seconds=offset)))
        return bj_dt.strftime(Mod)
    @staticmethod
    def log(content,show=True):
        Text=Util.GetDate() + ' ' + str(content)
        if show:
            print(Text)
        if Util.logs:
            Util.logs=Util.logs+'<br>'+Text
        else:
            Util.logs=Text
        sys.stdout.flush()
    @staticmethod
    def GetLoginParams(htmlsrc):
        result={}
        form=re.findall(r'<form.*?>(.*?)</form>',htmlsrc,re.DOTALL)
        if len(form)<1:
            return None
        form=form[0]
        #使用正则表达式匹配表单选项，减少对第三方库的依赖
        items=re.findall(r'<input.*?name=\"(.*?)\".*?>',form)
        for item in items:
            value=re.findall(r'<input.*?name=\"{}\".*?value=\"(.*?)\".*?>'.format(item),form)
            if item == "rememberMe":
                #result[item]='true'
                continue
            if len(value)>0:
                result[item]=value[0]
            else:
                result[item]=''
        return result
    @staticmethod
    def captchaOCR(image):
        try:
            if Util.OCRclient == None:
                Util.OCRclient = AipOcr(APP_ID, API_KEY, SECRET_KEY)
            options = {
                'detect_direction' : 'true',
                'language_type' : 'CHN_ENG',     
                'detect_language': 'false',
                'probability' : 'fasle',
            }
            # 调用通用文字识别接口  
            result = Util.OCRclient.basicGeneral(image,options)
            result=result['words_result'][0]
            text=result['words']
            text=text.replace(' ','')
            return text
        except :
            Util.log("百度OCR识别失败,请检查配置!")
            return ''
    @staticmethod
    def CookDict2Str(cookdic):
        k=len(cookdic)
        cookiestr=''
        for i,cookie in enumerate(cookdic):
            cookiestr=cookiestr+cookie+'='+cookdic[cookie]
            if i < k-1:
                cookiestr=cookiestr+';'
        return cookiestr
    @staticmethod
    def Login(user, apis):
        loginurl=apis['login-url']
        #解析login-url中的协议和host
        info=re.findall('(.*?)://(.*?)/',loginurl)[0]
        protocol=info[0]
        host=info[1]
        headers={
            'Host': host,
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 7.1.1; MI 6 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
            'X-Requested-With': 'com.wisedu.cpdaily'
        }
        #session存放最终cookies
        session=requests.Session()
        #poster发送中间POST请求,用于处理特殊cookie
        poster=requests.urllib3.PoolManager()
        try:
            res=session.get(url=loginurl,headers=headers)
        except:
            Util.log("学校登录服务器可能宕机了...")
            return None
        #存储cookies
        cookies=requests.utils.dict_from_cookiejar(session.cookies)
        #print(res.text)
        sault=re.findall(r'pwdDefaultEncryptSalt = "(.*?)";',res.text)
        #寻找加密盐
        if len(sault) > 0:
            sault=sault[0]
        else:
            sault=None
        PostUrl=re.findall('action=\"(.*?)\"',res.text)[0]
        PostUrl=protocol+"://"+host+PostUrl
        Params=Util.GetLoginParams(res.text)
        Params['username']=user['username']
        #放了加密盐值
        if sault:
            Params['password']=Util.AesEncrypt(Util.Randomstr(64)+user['password'],sault)
        else:
            Params['password']=user['password']
        LoginHeaders=headers
        LoginHeaders['Content-Type']='application/x-www-form-urlencoded'
        LoginHeaders['cookie']=Util.CookDict2Str(cookies)
        #判断是否需要验证码
        needcaptchaUrl='{}://{}/authserver/needCaptcha.html'.format(protocol,host)
        captchaUrl='{}://{}/authserver/captcha.html'.format(protocol,host)
        res=session.get(url='{}?username={}'.format(needcaptchaUrl,user['username']),headers=headers)
        if 'false' in res.text:
            needCaptcha=False
        else:
            needCaptcha=True
        if needCaptcha:
            for i in range(MAX_Captcha_Times):
                Captcha=session.get(url=captchaUrl,headers=headers)
                code=Util.captchaOCR(Captcha.content)
                #api qps限制
                time.sleep(0.5)
                if len(code) != 4:
                    continue
                Params['captchaResponse']=code
                res=poster.request('POST',loginurl,body=up.urlencode(Params),headers=LoginHeaders,redirect=False)
                if 'Location' in res.headers:
                    #验证码登录成功
                    break
                if i == MAX_Captcha_Times-1:
                    Util.log("验证码识别超过最大次数")
        else:
            res=poster.request('POST',loginurl,body=up.urlencode(Params),headers=LoginHeaders,redirect=False)
        if 'Location' not in res.headers:
            Util.log("登录失败")
            return None
        nexturl=res.headers['Location']
        #requests.session对于部分SET-COOKIE无法正常识别，需手动更新
        tmpcookies=res.headers.get_all('Set-Cookie')
        for tmp in tmpcookies:
            tmpcookie=re.findall('(.*?)=(.*?);',tmp)[0]
            cookies[tmpcookie[0]]=tmpcookie[1]
        headers['host']=apis['host']
        session.cookies = requests.utils.cookiejar_from_dict(cookies, cookiejar=None, overwrite=True)
        res=session.post(url=nexturl,headers=headers)
        return session
    @staticmethod
    def Randomstr(bits):
        base_str='1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        result=''
        while bits>0:
            bits-=1
            result+=base_str[random.randint(0,61)]
        return result
    @staticmethod
    #DES+base64加密
    def DESEncrypt(s,Key=DESKEY):
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(Key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()
    #AES-CBC-PCKS5+base64加密
    @staticmethod
    def AesEncrypt(text,key):
        #生成16位随机iv
        iv=Util.Randomstr(16)
        #AES-CBC
        Encrypter=pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key.encode('utf-8'),iv.encode('utf-8')))
        Encrypted=Encrypter.feed(text)
        Encrypted+=Encrypter.feed()
        return base64.b64encode(Encrypted).decode()