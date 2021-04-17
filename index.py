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
####################################################
##########!!!!!!单用户信息!!!#######################
###################################################
USERNAME = '你的学号'
PASSWORD = '你身份证后6位'
# 到点延迟多少秒签到，默认为0s
DELAY = 0
####################################################
###########!!!!!消息推送!!!!!#######################
###################################################
# push_plus推送token,可以实现微信推送日志(https://pushplus.hxtrip.com),不需要消息推送的话可以不填
PUSHPLUS_token = ''
# 日志推送级别
PUSH_LEVEL = 1
######################################################
############!!!!!百度OCR识别!!!!######################
#####################################################
# SWU一般情况下不需要验证码，输错3次密码后才会要验证码，可以不填
APP_ID = '你的APP_ID'
API_KEY = '你的API_KEY'
SECRET_KEY = '你的SECRET_KEY'
#######################################################
#################!!!!DES加密密钥!!!!###################
#######################################################
DESKEY = 'b3L26XNL'
APPVERSION = '8.2.22'
#######################################################
############！！！！获取任务的接口！！！！###############
#######################################################
# 由于寒假不需要查寝，没有整理查寝的项目
API = {
    'Sign': {
        'GETTasks': 'https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
        'GETDetail': 'https://{host}/wec-counselor-sign-apps/stu/sign/detailSignInstance',
        'GenInfo': 'https://{host}/wec-counselor-sign-apps/stu/sign/getStuSignInfosByWeekMonth',
        'PicUploadUrl': 'https://{host}/wec-counselor-sign-apps/stu/oss/getUploadPolicy',
        'GETPicUrl': 'https://{host}/wec-counselor-sign-apps/stu/sign/previewAttachment',
        'Submit': 'https://{host}/wec-counselor-sign-apps/stu/sign/submitSign'
    },
    'Attendance': {
        'GETTasks': 'https://{host}/wec-counselor-attendance-apps/student/attendance/getStuAttendacesInOneDay',
        'GETDetail': 'https://{host}/wec-counselor-attendance-apps/student/attendance/detailSignInstance',
        'GenInfo': 'https://{host}/wec-counselor-attendance-apps/student/attendance/getStuSignInfosByWeekMonth',
        'PicUploadUrl': 'https://{host}/wec-counselor-attendance-apps/student/attendance/getStsAccess',
        'GETPicUrl': 'https://{host}/wec-counselor-attendance-apps/student/attendance/previewAttachment',
        'Submit': 'https://{host}/wec-counselor-attendance-apps/student/attendance/submitSign'
    }
}
#######################################################
#####！！！！正常情况下下面代码不需要更新！！！！#########
#######################################################

#######################################################
#########！！！！热更新代码！！！！######################
#######################################################
if 'CLOUDUSERNAME' in locals().keys():
    USERNAME = locals().get('CLOUDUSERNAME')
if 'CLOUDPASSWORD' in locals().keys():
    PASSWORD = locals().get('CLOUDPASSWORD')
if 'CLOUDDELAY' in locals().keys():
    DELAY = locals().get('CLOUDDELAY')
if 'CLOUDPUSHTOKEN' in locals().keys():
    PUSHPLUS_token = locals().get('CLOUDPUSHTOKEN')
if 'CLOUDAPP_ID' in locals().keys():
    APP_ID = locals().get('CLOUDAPP_ID')
if 'CLOUDAPI_KEY' in locals().keys():
    API_KEY = locals().get('CLOUDAPI_KEY')
if 'CLOUDSECRET_KEY' in locals().keys():
    SECRET_KEY = locals().get('CLOUDSECRET_KEY')
if 'CLOUDPUSH_LEVEL' in locals().keys():
    PUSH_LEVEL = locals().get('CLOUDPUSH_LEVEL')
######################################################
############!!!热更新代码结束!!!#######################
######################################################
MAX_Captcha_Times = 20


class Util:  # 统一的类
    logs = 'V2021.4.17'
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
    def GetLoginParams(htmlsrc):
        result = {}
        form = re.findall(r'<form.*?>(.*?)</form>', htmlsrc, re.DOTALL)
        if len(form) < 1:
            return None
        form = form[0]
        # 使用正则表达式匹配表单选项，减少对第三方库的依赖
        items = re.findall(r'<input.*?name=\"(.*?)\".*?>', form)
        for item in items:
            value = re.findall(
                r'<input.*?name=\"{}\".*?value=\"(.*?)\".*?>'.format(item), form)
            if len(value) > 0:
                result[item] = value[0]
            else:
                result[item] = ''
        return result

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
    def CookDict2Str(cookdic):
        k = len(cookdic)
        cookiestr = ''
        for i, cookie in enumerate(cookdic):
            cookiestr = cookiestr+cookie+'='+cookdic[cookie]
            if i < k-1:
                cookiestr = cookiestr+';'
        return cookiestr

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
        # poster发送中间POST请求,用于处理特殊cookie
        poster = requests.urllib3.PoolManager()
        # SWU在网页这里没有直接放加密盐值
        try:
            res = session.get(url=loginurl, headers=headers)
        except:
            Util.log("学校登录服务器可能宕机了...")
            return None
        # 存储cookies
        cookies = requests.utils.dict_from_cookiejar(session.cookies)
        PostUrl = re.findall('action=\"(.*?)\"', res.text)[0]
        PostUrl = protocol+"://"+host+PostUrl
        Params = Util.GetLoginParams(res.text)
        Params['username'] = user['username']
        Params['password'] = user['password']
        LoginHeaders = headers
        LoginHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
        LoginHeaders['cookie'] = Util.CookDict2Str(cookies)
        # 判断是否需要验证码
        needcaptchaUrl = '{}://{}/authserver/needCaptcha.html'.format(
            protocol, host)
        captchaUrl = '{}://{}/authserver/captcha.html'.format(protocol, host)
        res = session.get(url='{}?username={}'.format(
            needcaptchaUrl, user['username']), headers=headers)
        if 'false' in res.text:
            needCaptcha = False
        else:
            needCaptcha = True
        if needCaptcha:
            for i in range(MAX_Captcha_Times):
                Captcha = session.get(url=captchaUrl, headers=headers)
                code = Util.captchaOCR(Captcha.content)
                # api qps限制
                time.sleep(0.5)
                if len(code) != 4:
                    continue
                Params['captchaResponse'] = code
                res = poster.request('POST', loginurl, body=up.urlencode(
                    Params), headers=LoginHeaders, redirect=False)
                if 'Location' in res.headers:
                    # 验证码登录成功
                    break
                if i == MAX_Captcha_Times-1:
                    Util.log("验证码识别超过最大次数")
        else:
            res = poster.request('POST', loginurl, body=up.urlencode(
                Params), headers=LoginHeaders, redirect=False)
        if 'Location' not in res.headers:
            Util.log("登录失败")
            return None
        nexturl = res.headers['Location']
        # requests.session对于部分SET-COOKIE无法正常识别，需手动更新
        tmpcookies = res.headers.get_all('Set-Cookie')
        for tmp in tmpcookies:
            tmpcookie = re.findall('(.*?)=(.*?);', tmp)[0]
            cookies[tmpcookie[0]] = tmpcookie[1]
        headers['host'] = School_Server_API['host']
        session.cookies = requests.utils.cookiejar_from_dict(
            cookies, cookiejar=None, overwrite=True)
        res = session.post(url=nexturl, headers=headers)
        return session

    @staticmethod
    # DES+base64加密
    def DESEncrypt(s, Key=DESKEY):
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(Key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    @staticmethod
    # 生成带有extension的headers
    def GenHeadersWithExtension(user, School_Server_API):
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
            'Host': School_Server_API['host'],
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
        }
        return headers

    @staticmethod
    # 生成正常POST请求的headers
    def GenNormalHears(School_Server_API):
        headers = {
            'Host': School_Server_API['host'],
            'Accept': 'application/json, text/plain, */*',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 7.1.1; MI 6 Build/NMF26X; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36  cpdaily/8.2.22 wisedu/8.2.22',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,en-US;q=0.8',
        }
        return headers

    @staticmethod
    # 检查是否在签到时间，如果是，则返回0，否则返回和开始时间的差值
    def TimeCheck(task):
        try:
            begin_Day = re.findall(
                r'([\d]+-[\d]+-[\d]+)', task['rateSignDate'])
            begin = begin_Day[0]+' '+task['rateTaskBeginTime']
            end = begin_Day[0]+' '+task['rateTaskEndTime']
        except:
            Util.log("未知任务"+'"'+task['taskName']+'"')
            return False
        # Util.log('"'+task['taskName']+'"'+'的签到时间为'+begin+'至'+end)
        utc_dt = datetime.utcnow().replace(tzinfo=timezone.utc)
        bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
        now = bj_dt.timetuple()
        #Util.log('执行函数时的时间为'+time.strftime("%Y-%m-%d %H:%M:%S",now))
        begin = time.strptime(begin, "%Y-%m-%d %H:%M")
        end = time.strptime(end, "%Y-%m-%d %H:%M")
        if now >= begin and now <= end:
            return 0
        else:
            now = time.mktime(now)
            begin = time.mktime(begin)
            # 返回距离开始的时间
            return begin-now
    # 通过pushplus推送消息

    @staticmethod
    def SendMessage(title: str, content: str, topic='', ctype='html'):
        if PUSHPLUS_token == '':
            Util.log("未配置pushplus的token，消息不会推送")
            return False
        data = {
            'token': PUSHPLUS_token,
            'title': title,
            'content': content,
            'topic': topic,
            'template': ctype
        }
        try:
            res = requests.post(
                url='https://pushplus.hxtrip.com/send', data=data)
            Util.log(res.json()['msg'])
        except:
            Util.log('发送失败')

    @staticmethod
    def GenDeviceID(username):
        # 生成设备id，根据用户账号生成,保证同一学号每次执行时deviceID不变，可以避免辅导员看到用新设备签到
        deviceId = ''
        random.seed(username.encode('utf-8'))
        for i in range(8):
            num = random.randint(97, 122)
            if (num*i+random.randint(1, 8)) % 3 == 0:
                deviceId = deviceId+str(num % 9)
            else:
                deviceId = deviceId+chr(num)
        deviceId = deviceId+'XiaomiMI6'
        return deviceId
# 任务模板，签到和查寝均继承模板


class TaskModel:
    def __init__(self, TaskType, School_Server_API, Showname, session, userBaseInfo):
        self.API = API[TaskType]
        self.Showname = Showname
        self.School_Server_API = School_Server_API
        self.session = session
        self.userBaseInfo = userBaseInfo
        self.real_taskname = ''

    def UpdateInfo(self, session, userBaseInfo, School_Server_API=None):
        # 更新数据
        self.session = session
        self.userBaseInfo = userBaseInfo
        if School_Server_API:
            School_Server_API = School_Server_API

    def GetTasks(self):
        res = self.session.post(
            url=self.API['GETTasks'].format(
                host=self.School_Server_API['host']),
            headers=Util.GenNormalHears(self.School_Server_API),
            data=json.dumps({})
        )
        res = res.json()
        if res['message'] == 'SUCCESS':
            return res['datas']
        else:
            Util.log('获取{}任务时出错,原因是'.format(self.Showname)+res['message'])
            return None

    def GetDetailTask(self, params):
        res = self.session.post(
            url=self.API['GETDetail'].format(
                host=self.School_Server_API['host']),
            headers=Util.GenNormalHears(self.School_Server_API),
            data=json.dumps(params))
        res = res.json()
        if res['message'] == 'SUCCESS':
            return res['datas']
        else:
            Util.log('获取{}任务详情时出错,原因是'.format(self.Showname)+res['message'])
            return None
    def GetSignedInfo(self,day=1):
        # 默认获取前一天的签到信息
        data = {"statisticYearMonth": Util.GetDate('%Y-%m', day)}
        headers = Util.GenNormalHears(self.School_Server_API)
        try:
            res = self.session.post(url=self.API['GenInfo'].format(
                host=self.School_Server_API['host']), data=json.dumps(data), headers=headers)
            signdays = res.json()['datas']['rows']
        except:
            Util.log("获取昨天签到信息时出错")
            return None
        yesterday = Util.GetDate('%Y-%m-%d', day)
        for signday in signdays:
            if signday['dayInMonth'] == yesterday:
                yesterday_info = signday
                break
        yesterday_signed = yesterday_info['signedTasks']
        params = {}
        signedTasksInfo = []
        for task in yesterday_signed:
            params['signInstanceWid'] = task['signInstanceWid']
            params['signWid'] = task['signWid']
            info = self.GetDetailTask(params)
            if info:
                signedTasksInfo.append(info)
        return signedTasksInfo

    # 模板下面的函数根据对应任务实现

    def GenConfig(self, signedTasksInfo):
        pass

    def fillForm(self, task, config):
        pass

    def submitForm(self, config):
        pass

    def Go(self, session=None, userBaseInfo=None, config=None, School_Server_API=None):
        pass
# 签到


class Sign(TaskModel):
    def __init__(self, School_Server_API, session, userBaseInfo):
        super().__init__('Sign', School_Server_API, '签到', session, userBaseInfo)

    def GenConfig(self, signedTasksInfo):
        config = {}
        for info in signedTasksInfo:
            extra = {}
            for item in info['signedStuInfo']['extraFieldItemVos']:

                extra[item['extraTitle']] = [item['extraFieldItem']]
            config[info['taskName']] = {
                'address': info['signAddress'],
                'lon': info['longitude'],
                'lat': info['latitude'],
                'abnormalReason': '',
                'photo': info['signPhotoUrl'],
                'extra': extra
            }
        return config

    def fillForm(self, task, config):
        form = {}
        config = config[task['taskName']]
        # 判断是否需要提交图片
        if task['isPhoto'] == 1:
            if config['photo'] != '':
                #fileName = self.uploadPicture(config['photo'])
                form['signPhotoUrl'] = config['photo']
            else:
                Util.log('"{}"需要照片，但未配置'.format(task['taskName']))
                return None
        else:
            form['signPhotoUrl'] = ''
    # 判断是否需要提交附加信息
        if task['isNeedExtra'] == 1:
            extraFields = task['extraField']
            # 根据设定内容填充表格
            defaults = config['extra']
            extraFieldItemValues = []
            # 遍历每条附加信息,这里，预设的值必须与选项顺序一一对应
            for extraField in extraFields:
                if extraField['title'] not in defaults:
                    Util.log('"{}"的选项"{}"配置出现问题,请检查"'.format(
                        task['taskName'], extraField['title']))
                    return None
                extraFieldItems = extraField['extraFieldItems']
                # 遍历附加信息的每一个选项
                for extraFieldItem in extraFieldItems:
                    # 如果是设定值，则选择
                    if extraFieldItem['content'] == defaults[extraField['title']][0]:
                        extraFieldItemValue = {'extraFieldItemValue': defaults[extraField['title']][0],
                                               'extraFieldItemWid': extraFieldItem['wid']}
                        extraFieldItemValues.append(extraFieldItemValue)
            # 处理带附加选项的签到
            form['extraFieldItems'] = extraFieldItemValues
        form['longitude'] = config['lon']
        form['latitude'] = config['lat']
        form['isMalposition'] = task['isMalposition']
        form['abnormalReason'] = config['abnormalReason']
        form['signInstanceWid'] = task['signInstanceWid']
        form['position'] = config['address']
        form['uaIsCpadaily'] = True
        form['signVersion'] = '1.0.0'
        return form

    def submitForm(self, config, form):
        res = self.session.post(
            url=self.API['Submit'].format(host=self.School_Server_API['host']),
            headers=Util.GenHeadersWithExtension(
                config, self.School_Server_API),
            data=json.dumps(form)
        )
        message = res.json()['message']
        if message == 'SUCCESS':
            Util.log('自动签到成功')
            if PUSH_LEVEL == 1:
                Util.SendMessage(
                    "自动签到成功", '"{}"已自动完成'.format(self.real_taskname))
            return True
        else:
            Util.log('自动签到失败，原因是：' + message)
            if PUSH_LEVEL < 2:
                Util.SendMessage("今日校园自动查寝失败", "自动查寝失败，原因是：" +
                                 message+" ,请手动签到，等待更新")
            return False
    # 指定config的参数会覆盖自动生成的参数

    def Go(self, session=None, userBaseInfo=None, config=None, School_Server_API=None):
        if session:
            self.UpdateInfo(session, userBaseInfo, School_Server_API)
        signedinfo = self.GetSignedInfo()
        autoconfig = self.GenConfig(signedinfo)
        if config:
            autoconfig.update(config)
        tasks = self.GetTasks()
        todotaskstype = []
        if len(tasks['unSignedTasks']) > 0:
            text = '未完成的签到任务:'
            for i, task in enumerate(tasks['unSignedTasks']):
                text = text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('unSignedTasks')
        if len(tasks['leaveTasks']) > 0:
            text = '请假的签到任务:'
            for i, task in enumerate(tasks['leaveTasks']):
                text = text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('leaveTasks')
        for todotype in todotaskstype:
            for i in range(0, len(tasks[todotype])):
                todoTask = tasks[todotype][i]
                params = {
                    'signInstanceWid': todoTask['signInstanceWid'],
                    'signWid': todoTask['signWid']
                }
                taskDetail = self.GetDetailTask(params)
                # 判断是否配置某个打卡选项
                if taskDetail['taskName'] not in autoconfig:
                    Util.log('"{}"昨天不存在或未签到'.format(taskDetail['taskName']))
                    Util.log("开始回滚以获取签到信息")
                    for i in range(30):
                        Util.log("回滚{}天".format(str(i+2)))
                        signedinfo=self.GetSignedInfo(i+2)
                        autoconfig=self.GenConfig(signedinfo)
                        if taskDetail['taskName'] in autoconfig:
                            Util.log("获取到签到信息，继续进行签到")
                            break
                if taskDetail['taskName'] not in autoconfig:
                    Util.log("回滚一月仍未获取到签到信息，可能是新发布的任务，跳过")
                    continue
                # 判断是否在签到时间
                t = Util.TimeCheck(taskDetail)
                if t != 0 and t > 60:  # 超过60秒则不再休眠
                    Util.log('"'+taskDetail['taskName']+'"'+"目前不在签到时间，跳过")
                    continue
                Form = self.fillForm(taskDetail, autoconfig)
                if Form == None:
                    continue
                submitinfo = {
                    'username': self.userBaseInfo['username'],
                    'lon': autoconfig[taskDetail['taskName']]['lon'],
                    'lat': autoconfig[taskDetail['taskName']]['lat'],
                    'deviceId': self.userBaseInfo['deviceId']
                }
                if t > 0:
                    t = t+DELAY
                    Util.log("休眠{}s后开始签到".format(str(t)))
                    time.sleep(t)
                self.real_taskname = taskDetail['taskName']
                self.submitForm(submitinfo, Form)
# 查寝


class Attendance(TaskModel):
    def __init__(self, School_Server_API, session, userBaseInfo):
        super().__init__('Attendance', School_Server_API, '查寝', session, userBaseInfo)

    def GenConfig(self, signedTasksInfo):
        config = {}
        for info in signedTasksInfo:
            config[info['taskName']] = {
                'address': info['signAddress'],
                'lon': info['longitude'],
                'lat': info['latitude'],
                'abnormalReason': '',
                'photo': info['signPhotoUrl'],
            }
        return config

    def fillForm(self, task, config):
        config = config[task['taskName']]
        form = {}
        form['signInstanceWid'] = task['signInstanceWid']
        form['longitude'] = config['lon']
        form['latitude'] = config['lat']
        form['isMalposition'] = task['isMalposition']
        form['abnormalReason'] = config['abnormalReason']
        if task['isPhoto'] == 1:
            if config['photo'] != '':
                #fileName = self.uploadPicture(config['photo'])
                form['signPhotoUrl'] = config['photo']
            else:
                Util.log('"{}"需要照片，但未配置'.format(task['taskName']))
                return None
        else:
            form['signPhotoUrl'] = ''
        form['position'] = config['address']
        form['uaIsCpadaily'] = True
        return form

    def submitForm(self, config, form):
        res = self.session.post(
            url=self.API['Submit'].format(host=self.School_Server_API['host']),
            headers=Util.GenHeadersWithExtension(
                config, self.School_Server_API),
            data=json.dumps(form)
        )
        message = res.json()['message']
        if message == 'SUCCESS':
            Util.log('自动查寝成功')
            if PUSH_LEVEL == 1:
                Util.SendMessage(
                    "自动查寝成功", '"{}"已自动完成'.format(self.real_taskname))
            return True
        else:
            Util.log('自动查寝失败，原因是：' + message)
            if PUSH_LEVEL < 2:
                Util.SendMessage("今日校园自动查寝失败", "自动查寝失败，原因是：" +
                                 message+" 请手动签到，等待更新")
            return False
    # 指定config的参数会覆盖自动生成的参数

    def Go(self, session=None, userBaseInfo=None, config=None, School_Server_API=None):
        if session:
            self.UpdateInfo(session, userBaseInfo, School_Server_API)
        signedinfo = self.GetSignedInfo()
        autoconfig = self.GenConfig(signedinfo)
        if config:
            autoconfig.update(config)
        tasks = self.GetTasks()
        todotaskstype = []
        if len(tasks['unSignedTasks']) > 0:
            text = '未完成的查寝任务:'
            for i, task in enumerate(tasks['unSignedTasks']):
                text = text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('unSignedTasks')
        if len(tasks['leaveTasks']) > 0:
            text = '请假的查寝任务:'
            for i, task in enumerate(tasks['leaveTasks']):
                text = text+str(i+1)+'.'+task['taskName']+' '
            Util.log(text)
            todotaskstype.append('leaveTasks')
        for todotype in todotaskstype:
            for i in range(0, len(tasks[todotype])):
                todoTask = tasks[todotype][i]
                params = {
                    'signInstanceWid': todoTask['signInstanceWid'],
                    'signWid': todoTask['signWid']
                }
                taskDetail = self.GetDetailTask(params)
                if taskDetail['taskName'] not in autoconfig:
                    Util.log('"{}"昨天不存在或未签到，跳过'.format(taskDetail['taskName']))
                    Util.log("开始回滚以获取签到信息")
                    for i in range(30):
                        Util.log("回滚{}天".format(str(i+2)))
                        signedinfo=self.GetSignedInfo(i+2)
                        autoconfig=self.GenConfig(signedinfo)
                        if taskDetail['taskName'] in autoconfig:
                            Util.log("获取到签到信息，继续进行签到")
                            break
                if taskDetail['taskName'] not in autoconfig:
                    Util.log("回滚一月仍未获取到签到信息，可能是新发布的任务，跳过")
                    continue
                # 判断是否在签到时间
                t = Util.TimeCheck(taskDetail)
                if t != 0 and t > 60:  # 超过60秒则不再休眠
                    Util.log('"'+taskDetail['taskName']+'"'+"目前不在签到时间，跳过")
                    continue
                Form = self.fillForm(taskDetail, autoconfig)
                if Form == None:
                    continue
                submitinfo = {
                    'username': self.userBaseInfo['username'],
                    'lon': autoconfig[taskDetail['taskName']]['lon'],
                    'lat': autoconfig[taskDetail['taskName']]['lat'],
                    'deviceId': self.userBaseInfo['deviceId']
                }
                if t > 0:
                    t = t+DELAY
                    Util.log("休眠{}s后开始签到".format(str(t)))
                    time.sleep(t)
                self.real_taskname = taskDetail['taskName']
                self.submitForm(submitinfo, Form)


def Do(School_Server_API, user):
    session = Util.Login(user, School_Server_API)
    if session:
        Util.log('登陆成功')
        userBaseInfo = {
            'username': user['username'],
            'deviceId': Util.GenDeviceID(user['username'])
        }
        Signer = Sign(School_Server_API, session, userBaseInfo)
        Attendancer = Attendance(School_Server_API, session, userBaseInfo)
        try:
            Signer.Go()
        except:
            Util.log("签到过程中出现异常")
            if PUSH_LEVEL < 2:
                Util.SendMessage("今日校园签到失败", "签到过程中出现异常，请手动签到")
        try:
            Attendancer.Go()
        except:
            Util.log("查寝过程中出现异常")
            if PUSH_LEVEL < 2:
                Util.SendMessage("今日校园查寝失败", "查寝过程中出现异常，请手动签到")
    else:
        if PUSH_LEVEL < 2:
            Util.SendMessage("今日校园签到失败", "登录过程中出现错误,如若经常发生，请修改执行时间")


def main():
    School_Server_API = {
        'login-url': 'http://authserverxg.swu.edu.cn/authserver/login?service=https%3A%2F%2Fswu.campusphere.net%2Fportal%2Flogin',
        'host': 'swu.campusphere.net'
    }
    user = {
        'username': USERNAME,
        'password': PASSWORD
    }
    Do(School_Server_API, user)
    if (PUSH_LEVEL > 1):
        Util.SendMessage('签到日志', Util.logs)
# 提供给腾讯云函数调用的启动函数


def main_handler(event, context):
    try:
        main()
    except Exception as e:
        Util.log(traceback.format_exc(), False)
        Util.SendMessage('出错了', Util.logs)
        raise e
    else:
        return 'success'


if __name__ == '__main__':
    print(main_handler({}, {}))
