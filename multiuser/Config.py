from DailyCp import Util,requests,json,time,AutoSign
from random import randint
apis={
    'login-url': 'http://authserverxg.swu.edu.cn/authserver/login?service=https%3A%2F%2Fswu.campusphere.net%2Fportal%2Flogin',
    'host': 'swu.campusphere.net'
    }
def GetDate(Mod='%Y-%m-%d',offset=0):
    date = time.strftime(Mod,time.localtime(time.time()+offset))
    return date
def GenInfo(username,password):
    session=Util.Login({'username':username,'password':password},apis)
    if session == None:
        return None
    #获取前一天的签到信息
    data={"statisticYearMonth":GetDate('%Y-%m',-86400)}
    headers=Util.GenNormalHears()
    headers['Content-Type']='application/json;charset=UTF-8'
    res=session.post(url='https://{}/wec-counselor-sign-apps/stu/sign/getStuSignInfosByWeekMonth'.format(apis['host']),data=json.dumps(data),headers=headers)
    signdays=res.json()['datas']['rows']
    yesterday=GetDate('%Y-%m-%d',-86400)
    deviceId=''
    for i in range(8):
        num=randint(97,122)
        if (num*i+randint(1,8))%3==0:
            deviceId=deviceId+str(num%9)
        else:
            deviceId=deviceId+chr(num)
    deviceId=deviceId+'XiaomiMI6'
    #读取前一天的签到信息
    one={
        'username':username,
        'password':password,
        'deviceId':deviceId,
    }
    for signday in signdays:
        if signday['dayInMonth'] == yesterday:
            yesterday_info=signday
            break
    yesterday_signed=yesterday_info['signedTasks']
    params={}
    for task in yesterday_signed:
        params['signInstanceWid']=task['signInstanceWid']
        params['signWid']=task['signWid']
        info=AutoSign.GetDetailTask(session,params,apis)
        extra={}
        for item in info['signedStuInfo']['extraFieldItemVos']:
            if item['isExtraFieldOtherItem'] == '1':
                extra[item['extraTitle']]=[item['extraFieldItem'],item['ExtraFieldOtherItem']]
            else:
                extra[item['extraTitle']]=[item['extraFieldItem']]
        one[info['taskName']]={
            'address':info['signAddress'],
            'lon':info['longitude'],
            'lat':info['latitude'],
            'abnormalReason':None,
            'photo':None,
            'extra':extra
        }
    return one
if __name__ == '__main__':
    result=[]
    while 1:
        username=input("输入学号:(直接回车结束)")
        if username == '':
            break
        password=input("输入密码:(直接回车结束)")
        if password == '':
            break
        result.append(GenInfo(username,password))
    with open('configs.json','w+',encoding='utf-8') as f:
        data=json.dumps(result,indent=4,ensure_ascii=False)
        f.write(data)