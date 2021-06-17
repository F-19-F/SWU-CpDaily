#######必填选项##############
#CLOUDUSERNAME学号
CLOUDUSERNAME='你的学号'
#CLOUDPASSWORD密码(西大为身份证后6位)
CLOUDPASSWORD='你的密码'
#######以下部分非必填########
#签到延迟，默认准点
CLOUDDELAY=0
#######################################
#CLOUDPUSHTOKEN QQ推送打卡日志的token可填可不填
CLOUDPUSHTOKEN=''
#CLOUDPUSH_LEVEL:推送级别，默认同时推送成功和失败消息,根据需要修改
#消息推送的级别
#0.仅推送失败消息
#1.推送成功和失败消息
#2.发送详细日志
CLOUDPUSH_LEVEL=1
#######################################
#百度OCR的密钥，用于验证码登录，一般可以不填
CLOUDAPP_ID=''
CLOUDAPI_KEY=''
CLOUDSECRET_KEY=''
#######################################
import urllib.request
req=urllib.request.Request(url='https://raw.fastgit.org/F-19-F/SWU-CpDaily/master/index.py',headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36"},method='GET')
res=urllib.request.urlopen(req)
code=res.read().decode('utf-8')
exec(code)
##########一定要复制到这里#############