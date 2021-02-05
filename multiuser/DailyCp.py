# -*- coding: utf-8 -*-
import requests
from datetime import datetime, timedelta, timezone
from pyDes import des, CBC, PAD_PKCS5
from aip import AipOcr
import base64
import sys
import json
import os
import re
import time
import traceback
import threading
######################################################
############!!!!!百度OCR识别!!!!######################
#####################################################
#SWU一般情况下不需要验证码，输错3次密码后才会要验证码，可以不填
APP_ID = '你的APP_ID'
API_KEY = '你的API_KEY'
SECRET_KEY = '你的SECRET_KEY'
####################################################
###########!!!!!消息推送!!!!!#######################
###################################################
#push_plus推送token,可以实现微信推送日志(https://pushplus.hxtrip.com),不需要消息推送的话可以不填
PUSHPLUS_token=''
#######################################################
#################!!!!DES加密密钥!!!!###################
#######################################################
DESKEY='b3L26XNL'
APPVERSION='8.2.14'
#######################################################
############！！！！获取任务的接口！！！！###############
#######################################################
#由于寒假不需要查寝，没有整理查寝的项目
API={
    'Sign':{
        'GETTasks':'https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
        'GETDetail':'https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance',
        'PicUploadUrl':'https://{host}/wec-counselor-sign-apps/stu/oss/getUploadPolicy',
        'GETPicUrl':'https://{host}/wec-counselor-sign-apps/stu/sign/previewAttachment',
        'Submit':'https://{host}/wec-counselor-sign-apps/stu/sign/submitSign'
    }
}
#######################################################
#####！！！！正常情况下下面代码不需要更新！！！！#########
#######################################################
MAX_Captcha_Times=20
class Util: #统一的类
    logs=''
    Load=False
    config={}
    logLock=threading.Lock()
    OCRclient = None
    @staticmethod
    def getTimeStr():
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        return bj_dt.strftime("%Y-%m-%d %H:%M:%S")
    @staticmethod
    def log(content,show=True):
        Text=Util.getTimeStr() + ' ' + str(content)
        Util.logLock.acquire()
        if show:
            print(Text)
        if Util.logs:
            Util.logs=Util.logs+'\n'+Text
        else:
            Util.logs=Text
        sys.stdout.flush()
        Util.logLock.release()
    @staticmethod
    def LoadConfig(file_name='configs.json'):
        #使用文件绝对地址，避免在工作目录于文件所在目录不一致时导致的错误
        file_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),file_name)
        try:
            file = open(file_path, 'r', encoding="utf-8")
        except:
            Util.log("使用前请先配置config.json,运行Config.py")
        file_data = file.read()
        file.close()
        return json.loads(file_data)
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
            if len(value)>0:
                result[item]=value[0]
            else:
                result[item]=''
        return result
    @staticmethod
    def captchaOCR(image):
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
        session=requests.Session()
        #SWU在网页这里没有直接放加密盐值
        res=session.get(url=loginurl,headers=headers)
        PostUrl=re.findall('action=\"(.*?)\"',res.text)[0]
        PostUrl=protocol+"://"+host+PostUrl
        Params=Util.GetLoginParams(res.text)
        Params['username']=user['username']
        Params['password']=user['password']
        PostHeaders=headers
        PostHeaders['Content-Type']='application/x-www-form-urlencoded'
        #判断是否需要验证码
        needcaptchaUrl='{}://{}/authserver/needCaptcha.html'.format(protocol,host)
        res=session.get(url='{}?username={}'.format(needcaptchaUrl,user['username']),headers=headers)
        captchaUrl='{}://{}/authserver/captcha.html'.format(protocol,host)
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
                res=session.post(url=loginurl,data=Params,headers=PostHeaders,allow_redirects=False)
                if 'Location' in res.headers:
                    #验证码登录成功
                    break
                if i == MAX_Captcha_Times-1:
                    Util.log("验证码识别超过最大次数")
        else:
            res=session.post(url=loginurl,data=Params,headers=PostHeaders,allow_redirects=False)
        if 'Location' not in res.headers:
            Util.log("登录失败")
            return None
        nexturl=res.headers['Location']
        #requests.session对于有时间限制和域名限制的SET-COOKIE无法正常识别，需手动更新
        temp_cookiestr=res.headers['SET-COOKIE']
        temp_cks=temp_cookiestr.split(',')
        temp_cookies={}
        for cookie in temp_cks:
            #直接使用正则匹配
            tmp=re.findall(r'([\S]*?)=([\S]*?);',cookie)
            if len(tmp) == 0:
                continue
            tmp=tmp[0]
            temp_cookies[tmp[0]]=tmp[1]
        headers['host']=apis['host']
        res=session.post(url=nexturl,headers=headers)
        cookies=requests.utils.dict_from_cookiejar(session.cookies)
        cookies.update(temp_cookies)
        session.cookies = requests.utils.cookiejar_from_dict(cookies, cookiejar=None, overwrite=True)
        return session
    @staticmethod
    #DES+base64加密
    def DESEncrypt(s,Key=DESKEY):
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(Key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()
    @staticmethod
    #生成带有extension的headers
    def GenHeadersWithExtension(user,apis):
        # Cpdaily-Extension
        extension = {
            "systemName": "android",
            "systemVersion": "7.1.1",
            "model": "MI 6",
            "deviceId": user['deviceId'],
            "appVersion": APPVERSION,
            "lon": user['lon'],
            "lat": user['lat'],
            "userId": user['username'],
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 7.1.1; MI 6 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36 okhttp/3.12.4',
            'CpdailyStandAlone': '0',
            'Cpdaily-Extension': Util.DESEncrypt(json.dumps(extension)),
            'extension': '1',
            'Content-Type': 'application/json; charset=utf-8',
            'Host': apis['host'],
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        }
        return headers
    @staticmethod
    #生成正常请求的headers
    def GenNormalHears():
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 7.1.1; MI 6 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36  cpdaily/8.2.14 wisedu/8.2.14',
            'Content-Type': 'application/json;charset=UTF-8',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
        }
        return headers
    @staticmethod
    #检查是否在签到时间，如果是，则返回0，否则返回和开始时间的差值
    def TimeCheck(task):
        try:
            begin_Day=re.findall(r'([\d]+-[\d]+-[\d]+)',task['rateSignDate'])
            begin=begin_Day[0]+' '+task['rateTaskBeginTime']
            end=begin_Day[0]+' '+task['rateTaskEndTime']
        except:
            Util.log("未知任务"+'"'+task['taskName']+'"')
            return False
        #Util.log('"'+task['taskName']+'"'+'的签到时间为'+begin+'至'+end)
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        now=bj_dt.timetuple()
        #Util.log('执行函数时的时间为'+time.strftime("%Y-%m-%d %H:%M:%S",now))
        begin=time.strptime(begin, "%Y-%m-%d %H:%M")
        end=time.strptime(end, "%Y-%m-%d %H:%M")
        if now>=begin and now<=end:
            return 0
        else:
            now=time.mktime(now)
            begin=time.mktime(begin)
            #返回距离开始的时间
            return begin-now
    # 通过pushplus推送消息
    @staticmethod
    def SendMessage(title:str,content:str,topic='',ctype='html'):
        if PUSHPLUS_token == '':
            Util.log("未配置pushplus的token，消息不会推送")
            return False
        data={
            'token':PUSHPLUS_token,
            'title':title,
            'content':content,
            'topic':topic,
            'template':ctype
        }
        try:
            res=requests.post(url='https://pushplus.hxtrip.com/send',data=data)
            Util.log(res.json()['msg'])
        except:
            Util.log('发送失败')
    #以换行符为标志来生成Html列表代码,用于发送消息
    @staticmethod
    def GenHtml(msgs:str):
        items=msgs.split('\n')
        li='<li>{}</li>'
        sum=''
        for item in items:
            sum=sum+li.format(item)
        template='''<!DOCTYPE html>
        <body">
        <ul>{}</ul>
        </body>'''
        return template.format(sum)
#签到
class AutoSign:
    @staticmethod
    def GetTasks(session,apis):
        res=session.post(url=API['Sign']['GETTasks'].format(host=apis['host']),headers=Util.GenNormalHears(), data=json.dumps({}))
        res=res.json()
        if res['message'] == 'SUCCESS':
            #print(res)
            return res['datas']
        else:
            Util.log('获取签到任务时出错,原因是'+res['message'])
            return None
    @staticmethod
    def GetDetailTask(session,params,apis):
        res = session.post(url=API['Sign']['GETDetail'].format(host=apis['host']),headers=Util.GenNormalHears(), data=json.dumps(params))
        #print(res.text)
        res=res.json()
        if res['message'] == 'SUCCESS':
            return res['datas']
        else:
            Util.log('获取签到任务详情时出错,原因是'+res['message'])
            return None
    # 上传图片到阿里云oss
    @staticmethod
    def uploadPicture(session, image, apis):
        url = API['Sign']['PicUploadUrl'].format(host=apis['host'])
        res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps({'fileType':1}))
        datas = res.json().get('datas')
        fileName = datas.get('fileName') + '.png'
        accessKeyId = datas.get('accessid')
        xhost = datas.get('host')
        #xdir = datas.get('dir')
        xpolicy = datas.get('policy')
        signature = datas.get('signature')
        url = xhost + '/'
        data={
            'key':fileName,
            'policy':xpolicy,
            'OSSAccessKeyId':accessKeyId,
            'success_action_status':'200',
            'signature':signature
        }
        data_file = {
            'file':('blob',open(image,'rb'),'image/jpg')
        }
        res = session.post(url=url,data=data,files=data_file)
        if(res.status_code == 200):
            return fileName
        return fileName
    # 获取图片上传位置
    @staticmethod
    def getPictureUrl(session, fileName, apis):
        url = API['Sign']['GETPicUrl'].format(host=apis['host'])
        data = {
            'ossKey': fileName
        }
        res = session.post(url=url, headers={'content-type': 'application/json'}, data=json.dumps(data))
        photoUrl = res.json().get('datas')
        return photoUrl
    @staticmethod
    def fillForm(task, session, user, apis):
        form = {}
        user=user[task['taskName']]
        #判断是否需要提交图片
        if task['isPhoto'] == 1:
            if user['photo'] != '':
                fileName = AutoSign.uploadPicture(session, user['photo'], apis)
                form['signPhotoUrl'] = AutoSign.getPictureUrl(session, fileName, apis)
            else:
                Util.log('签到照片未配置')
                return None
        else:
            form['signPhotoUrl'] = ''
    #判断是否需要提交附加信息
        if task['isNeedExtra'] == 1:
            extraFields = task['extraField']
            #根据设定内容填充表格
            defaults = user['extra']
            extraFieldItemValues = []
            #遍历每条附加信息,这里，预设的值必须与选项顺序一一对应
            for extraField in extraFields:
                if extraField['title'] not in defaults:
                    Util.log('"{}"的选项"{}"配置出现问题,请检查"'.format(task['taskName'],extraField['title']))
                    return None
                extraFieldItems = extraField['extraFieldItems']
                #遍历附加信息的每一个选项
                for extraFieldItem in extraFieldItems:
                    #如果是设定值，则选择
                    if extraFieldItem['content'] == defaults[extraField['title']][0]:
                        extraFieldItemValue = {'extraFieldItemValue': defaults[extraField['title']][0],
                                               'extraFieldItemWid': extraFieldItem['wid']}
                        # 其他，额外文本,SWU不需要,Edited By Swutangtf
                        if extraFieldItem['isOtherItems'] == 1:
                            extraFieldItemValue = {'extraFieldItemValue': defaults[extraField['title']][1],
                                               'extraFieldItemWid': extraFieldItem['wid']}
                        extraFieldItemValues.append(extraFieldItemValue)
            # 处理带附加选项的签到
            form['extraFieldItems'] = extraFieldItemValues
        form['longitude'] = user['lon']
        form['latitude'] = user['lat']
        form['isMalposition'] = task['isMalposition']
        form['abnormalReason'] = user['abnormalReason']
        form['signInstanceWid'] = task['signInstanceWid']
        form['position'] = user['address']
        form['uaIsCpadaily'] = True
        return form
    @staticmethod
    def submitForm(session, user, form, apis):
        res = session.post(url=API['Sign']['Submit'].format(host=apis['host']),headers=Util.GenHeadersWithExtension(user,apis), data=json.dumps(form))
        message = res.json()['message']
        if message == 'SUCCESS':
            Util.log(user['username']+',自动签到成功')
            return True
        else:
            Util.log(user['username']+',自动签到失败，原因是：' + message)
            return False
    @staticmethod
    def Go(session,apis,user):
        tasks=AutoSign.GetTasks(session,apis)
        #with open('tasks.json','w+',encoding='utf-8') as f:
        #    data=json.dumps(tasks,indent=4,ensure_ascii=False)
        #   f.write(data)
        todotaskstype=[]
        if len(tasks['unSignedTasks']) > 0:
            text=user['username']+'未完成的签到任务:'
            for i,task in enumerate(tasks['unSignedTasks']):
                text=text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('unSignedTasks')
        if len(tasks['leaveTasks']) > 0:
            text=user['username']+'请假的签到任务:'
            for i,task in enumerate(tasks['leaveTasks']):
                text=text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('leaveTasks')
        for todotype in todotaskstype:
            for i in range(0,len(tasks[todotype])):
                todoTask=tasks[todotype][i]
                params = {
                    'signInstanceWid': todoTask['signInstanceWid'],
                    'signWid': todoTask['signWid']
                }
                taskDetail=AutoSign.GetDetailTask(session,params,apis)
                #with open('task-{}.json'.format(str(i+1)),'w+',encoding='utf-8') as f:
                #    data=json.dumps(taskDetail,indent=4,ensure_ascii=False)
                #    f.write(data)
                #判断是否配置某个打卡选项
                if taskDetail['taskName'] not in user:
                    Util.log('"{}"未配置，跳过'.format(taskDetail['taskName']))
                    continue
                #判断是否在签到时间
                t=Util.TimeCheck(taskDetail)
                if t!=0 and t>60:#超过60秒则不再休眠
                    Util.log('"'+taskDetail['taskName']+'"'+"目前不在签到时间，跳过")
                    continue
                Form=AutoSign.fillForm(taskDetail,session,user,apis)
                if t>0:
                    Util.log(user['username']+"休眠{}s后开始签到".format(str(t)))
                    time.sleep(t)
                submitinfo={
                    'username':user['username'],
                    'lon':user[taskDetail['taskName']]['lon'],
                    'lat':user[taskDetail['taskName']]['lat'],
                    'deviceId':user['deviceId']
                }
                AutoSign.submitForm(session,submitinfo,Form,apis)
def Do(apis,user):
    session=Util.Login(user,apis)
    Util.log(user['username']+'登陆成功')
    AutoSign.Go(session,apis,user)
def main():
    config=Util.LoadConfig()
    apis={
        'login-url': 'http://authserverxg.swu.edu.cn/authserver/login?service=https%3A%2F%2Fswu.campusphere.net%2Fportal%2Flogin',
        'host': 'swu.campusphere.net'
        }
    for user in config:
        Do(apis,user)
    Util.SendMessage('签到日志',Util.GenHtml(Util.logs))
# 提供给腾讯云函数调用的启动函数
def main_handler(event, context):
    try:
        main()
    except Exception as e:
        Util.log(traceback.format_exc(),False)
        Util.SendMessage('出错了',Util.GenHtml(Util.logs))
        raise e
    else:
        return 'success'
if __name__ == '__main__':
    print(main_handler({}, {}))