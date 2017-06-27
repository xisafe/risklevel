#!/usr/bin/env python
# encoding: utf-8
"""
@version: 1.0
@author: liaowm
@site: http://www.lianlianpay.com
@software: PyCharm
@file: http.py
@time: 2017/6/26 17:50

list.txt写入需要查询的ip和电话
"""
import urllib2
import json
import re
import hmac
from hashlib import sha1
import base64

def levelip(ip,key,Token):
    data="{\"type\":\"IP\",\"value\":\""+ip+"\",\"scene\":\"login\",\"token\":\""+key+"\"}"
    sign=hmac.new(Token,data,sha1).digest()
    sign=base64.b64encode(sign)
    data = {
        "type": "Mobile",
        "value": ip,
        "scene": "login",
        "token": key,
        "sign": sign
        }
    headers = {'Content-Type': 'application/json'}
    request = urllib2.Request(url='http://api-security.ctrip.com/secsaas-service/services/risk', headers=headers, data=json.dumps(data))
    response = urllib2.urlopen(request)
    level= response.read()[20:21]
    if level=="0":
        print ip+u"--------无风险-在Saas风险库对应场景内无匹配数据"
    elif level=="1":
        print ip+u"--------风险等级为1-在Saas风险库对应场景内，风险等级低"
    elif level =="2":
        print ip+u"--------风险等级为2-在Saas风险库对应场景内，风险等级较低"
    elif level =="3":
        print ip+u"--------风险等级为3-在Saas风险库对应场景内，风险等级较高"
    elif level == "4":
        print ip+u"--------风险等级为4-在Saas风险库对应场景内，风险等级最高"

def leveltel(tel,key,Token):
    data="{\"type\":\"Mobile\",\"value\":\""+tel+"\",\"scene\":\"login\",\"token\":\""+key+"\"}"
    sign=hmac.new(Token,data,sha1).digest()
    sign=base64.b64encode(sign)
    data = {
        "type": "Mobile",
        "value": tel,
        "scene": "login",
        "token": key,
        "sign": sign
        }
    headers = {'Content-Type': 'application/json'}
    request = urllib2.Request(url='http://api-security.ctrip.com/secsaas-service/services/risk', headers=headers, data=json.dumps(data))
    response = urllib2.urlopen(request)
    level= response.read()[17:18]
    if level=="0":
        print tel+u"--------无风险-在Saas风险库对应场景内无匹配数据"
    elif level=="1":
        print tel+u"--------风险等级为1-在Saas风险库对应场景内，风险等级低"
    elif level =="2":
        print tel+u"--------风险等级为2-在Saas风险库对应场景内，风险等级较低"
    elif level =="3":
        print tel+u"--------风险等级为3-在Saas风险库对应场景内，风险等级较高"
    elif level =="4":
        print tel+u"--------风险等级为4-在Saas风险库对应场景内，风险等级最高"

if __name__ == '__main__':
    list = open('list.txt', 'r')
    Token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" #修改这里的Token，通过携程发送到自己邮箱
    key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"    #修改这里的key，在携程安全平台获取
    for line in list.readlines():
        line = line.strip()
        tel=re.compile("^0\d{2,3}\d{7,8}$|^1[358]\d{9}$|^147\d{8}")
        ip = re.compile("^((?:(2[0-4]\d)|(25[0-5])|([01]?\d\d?))\.){3}(?:(2[0-4]\d)|(255[0-5])|([01]?\d\d?))$")
        telmatch = tel.match(line)
        if telmatch:
            leveltel(telmatch.group(),key,Token)
        else:
            ipmatch = ip.match(line)
            if ipmatch:
                levelip(ipmatch.group(),key,Token)
            else:
                print(line+u"--------不是IP或者手机号")
