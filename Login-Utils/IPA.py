# -*- coding: utf-8 -*-
import requests
from datetime import datetime, timedelta, timezone
from pyDes import des, CBC, PAD_PKCS5
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
class Util:  # 统一的类
    logs = 'IPA-Login'
    OCRclient = None

    @staticmethod
    def GetDate(Mod='%Y-%m-%d %H:%M:%S', offset=0):
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        bj_dt=bj_dt-timedelta(days=offset)
        return bj_dt.strftime(Mod)

    @staticmethod
    def log(content, show=True):
        Text = Util.GetDate() + ' ' + str(content)
        if show:
            print(Text)
        if Util.logs:
            Util.logs = Util.logs+'<br>'+Text
        else:
            Util.logs = Text
        sys.stdout.flush()

    @staticmethod
    def captchaOCR(image):
        try:
            if Util.OCRclient == None:
                Util.OCRclient = AipOcr(APP_ID, API_KEY, SECRET_KEY)
            options = {
                'detect_direction': 'true',
                'language_type': 'CHN_ENG',
                'detect_language': 'false',
                'probability': 'fasle',
            }
            # 调用通用文字识别接口
            result = Util.OCRclient.basicGeneral(image, options)
            result = result['words_result'][0]
            text = result['words']
            text = text.replace(' ', '')
            return text
        except:
            Util.log("百度OCR识别失败,请检查配置!")
            return ''

    @staticmethod
    def Login(user, School_Server_API):
        loginurl = School_Server_API['login-url']
        # 解析login-url中的协议和host
        info = re.findall('(.*?)://(.*?)/', loginurl)[0]
        protocol = info[0]
        host = info[1]
        headers = {
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
        # session存放最终cookies
        session = requests.Session()
        try:
            res = session.get(url=loginurl, headers=headers)
        except:
            Util.log("学校登录服务器可能宕机了...")
            return None
        #获取重定向url中的lt
        lt = re.findall('_2lBepC=(.*)&*', res.url)
        if len(lt) == 0:
            Util.log("获取lt失败")
            return None
        lt=lt[0]
        PostUrl = '{}://{}/iap/doLogin'.format(protocol,host)
        Params = {}
        Params['username'] = user['username']
        Params['password'] = user['password']
        Params['rememberMe'] = 'false'
        Params['mobile'] = ''
        Params['dllt'] = ''
        Params['captcha'] = ''
        ltUrl='{}://{}/iap/security/lt'.format(protocol,host)
        LoginHeaders = headers
        LoginHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
        res=session.post(url=ltUrl,data={'lt':lt},headers=LoginHeaders)
        if res.status_code != 200:
            Util.log("申请lt失败")
            return None
        res=res.json()['result']
        Params['lt']=res['_lt']
        #新版验证码，直接POST，结果会说明是否需要验证码
        res = session.post(PostUrl,data=Params,headers=LoginHeaders,allow_redirects=False)
        if 'Location' not in res.headers:
            reason=res.json()['resultCode']
            if reason == 'FORCE_MOD_PASS':
                Util.log("请重置密码后重试！")
                return None
            elif reason == 'FAIL_UPNOTMATCH':
                Util.log("用户名或密码错误！")
                return None
            #需要验证码登录
            elif reason == 'CAPTCHA_NOTMATCH':
                captchaUrl = '{}://{}/iap/generateCaptcha?ltId={}'.format(protocol, host,Params['lt'])
                for i in range(MAX_Captcha_Times):
                    Captcha = session.get(url=captchaUrl, headers=headers)
                    code = Util.captchaOCR(Captcha.content)
                    # api qps限制
                    time.sleep(0.5)
                    if len(code) != 5:
                        continue
                    Params['captcha'] = code
                    res = session.post(PostUrl,data=Params,headers=LoginHeaders,allow_redirects=False)
                    if 'Location' in res.headers:
                        # 验证码登录成功或者密码错误
                        break
                    elif res.json()['resultCode'] == 'FAIL_UPNOTMATCH':
                        Util.log("用户名或密码错误！")
                        return None
                    if i == MAX_Captcha_Times-1:
                        Util.log("验证码识别超过最大次数")
        nexturl = res.headers['Location']
        headers['host'] = School_Server_API['host']
        res = session.post(url=nexturl, headers=headers)
        return session