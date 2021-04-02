# 西南大学今日校园自动签到-python
# 纯python实现的今日校园自动打卡
# 本项目仅供学习交流使用，如作他用所承受的任何直接、间接法律责任一概与作者无关
## 优点:
#### - 1.懒人版不需要配置签到地址等信息，自动根据昨天打卡地址打卡
#### - 2.代码可以热更新，部署一次，基本上不用再管，需要更新签到地址时只需要在手机上更新一次签到即可
#### - 3.不依赖于第三方登录服务器，信息更安全
#### - 4.灵活度高，更新简单，今日校园更新，项目可以很快跟进
#### - 5.模块化程度高，添加查寝和信息收集简单
#### ~~项目码云地址:SWU-CpDaily~~，由于特殊原因,码云仓库已经删掉了      
## 使用方法
### 单用户懒人版
#### - 1.打开[腾讯云云函数](https://console.cloud.tencent.com/scf)并扫码登录,完成实名认证
#### - 2.进入层，选择新建层 ![avatar](./tutorial/新建层1.png)
#### - 3.将项目中的Packages.zip(可以在[release](https://github.com/F-19-F/SWU-CpDaily/releases/tag/1.1)中下载，clone后用项目中的也可以)上传到层中，运行环境选择python3.6 ![avatar](./tutorial/新建层2.png)
#### - 4.进入函数服务，选择新建 ![avatar](./tutorial/新建函数0.png)
#### - 5.按照图设置好，名称自己定，运行环境选择python3.6 ![avatar](./tutorial/新建函数1.png)
#### - 5.在在线代码编辑器中将项目的index.py上传，可以直接复制内容,并将代码中对应部分换成你的学号和身份证后6位。如果你不想以后更新时更新代码（~~当懒人~~），建议直接复制下面这几行代码到云函数，修改学号和密码即可。会自动拉取项目代码签到。
```
import urllib.request
res=urllib.request.urlopen(url='https://raw.githubusercontent.com/F-19-F/SWU-CpDaily/master/index.py')
code=res.read().decode('utf-8')
#######-----单用户配置----##############
#CLOUDUSERNAME学号
CLOUDUSERNAME='你的学号'
#CLOUDPASSWORD密码(西大为身份证后6位)
CLOUDPASSWORD='你身份证后6位'
#签到延迟，默认准点
CLOUDDELAY=0
#######################################
#CLOUDPUSHTOKEN微信推送打卡日志的token可填可不填
CLOUDPUSHTOKEN=''
#CLOUDPUSH_LEVEL:推送级别，默认同时推送成功和失败消息,根据需要修改
#消息推送的级别
#0.仅推送失败消息
#1.推送成功和失败消息
#2.发送详细日志
CLOUDPUSH_LEVEL=1
#######################################
#百度OCR的密钥，一般可以不填
CLOUDAPP_ID=''
CLOUDAPI_KEY=''
CLOUDSECRET_KEY=''
#######################################
exec(code)
```
![avatar](./tutorial/新建函数2.png)
#### - 6.往下拉，将高级配置中的执行超时时间设为60s ![avatar](./tutorial/新建函数3.png)
#### - 7.进入层配置，选择添加层 ![avatar](./tutorial/新建函数4.png)
#### - 8.选择第一步创建的层 ![avatar](./tutorial/新建函数5.png)
#### - 9.保存 ![avatar](./tutorial/新建函数6.png)
#### - 10.打开刚才创建的云函数 ![avatar](./tutorial/新建函数7.png)
#### - 11.拉到最底下测试一下 ![avatar](./tutorial/新建函数8.png)
#### - 12.等待测试出来结果，正常情况结果如图 ![avatar](./tutorial/测试.png)   
#### - 13.进入触发管理，新建触发，并按图设置，Cron表达式"30 59 06,18 * * * *"表示每天6:50:30和18:59:30执行签到，程序会自动等待至签到时间签到 ![avatar](./tutorial/创建定时触发.png)
#### - 如果想把签到结果推送到微信，请打开[PUSH](https://pushplus.hxtrip.com/login?redirectUrl=/message)扫码关注公众号后复制网页中的token到代码中token对应的位置,签到日志会通过公众号发送到你的微信 ![avatar](./tutorial/消息推送.png)
## Enjoy it!


#### ~~多用户版可以配置多人打卡签到,就简单说一下，项目中multiuser中的代码是多用户版本，本地执行Config.py后输入学号和密码，会生成configs.json,把configs.json和DailyCp.py上传到云函数定时执行即可~~,多用户版本已经删除
##  最后注意一下，这个只针对西南大学哦，其他学校可以按照这个项目的思路改写