# -*- coding: utf-8 -*-
import re, time, datetime
import requests
import os
import httpx
import hmac, hashlib
import base64, uuid
import math, random
import httpx,json
from bs4 import BeautifulSoup

def lawtimeapi(method, path, token):
    '''
    阿里云网关请求方法
    :param path: 请求路径 (不包括域名)
    :param method: 请求方式 get/post
    :param params: get请求中query参数
    :param data: post请求里的body参数
    :return: 响应
    '''
    # 初始化请求头
    xcanonce = str(uuid.uuid1())
    if token == '':
        headers = {
            "X-Ca-Key": "25862410",
            "X-Ca-Stage": "RELEASE",
            "X-Ca-Nonce": xcanonce,
            "X-Ca-Signature-Headers": "X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Stage",
            "x-ca-signature-method": "HmacSHA256",
            "X-Ca-Signature": ""
        }
    else:
        headers = {
            "w-ca-token": token,
            "X-Ca-Key": "25862410",
            "X-Ca-Stage": "RELEASE",
            "X-Ca-Nonce": xcanonce,
            "X-Ca-Signature-Headers": "X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Stage",
            "x-ca-signature-method": "HmacSHA256",
            "X-Ca-Signature": ""
        }
    # 参与签名的参数
    date = '';
    textToSign = "";
    textToSign += method + "\n";
    textToSign += "*/*" + "\n";
    textToSign += date + "\n";
    textToSign += "application/x-www-form-urlencoded; charset=UTF-8" + "\n";
    textToSign += date + "\n";
    textToSign += "X-Ca-Key:25862410" + "\n";
    textToSign += "X-Ca-Nonce:" + xcanonce + "\n";
    textToSign += "X-Ca-Signature-Method:HmacSHA256" + "\n";
    textToSign += "X-Ca-Stage:RELEASE" + "\n";
    textToSign += path;
    # 进行签名
    signature = base64.b64encode(
        hmac.new("b8156787e666454574e4b843187bc57c".encode('utf-8'), textToSign.encode('utf-8'),
                 digestmod=hashlib.sha256).digest()).decode("utf-8")
    # 把签名放进headers
    headers['X-Ca-Signature'] = signature
    headers[
        'user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'
    headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    return headers

def findlawapi(method, path, token):
    '''
    阿里云网关请求方法
    :param path: 请求路径 (不包括域名)
    :param method: 请求方式 get/post
    :param params: get请求中query参数
    :param data: post请求里的body参数
    :return: 响应
    '''
    # 初始化请求头
    xcanonce = str(uuid.uuid1())
    if token == '':
        headers = {
            "X-Ca-Key": "203773710",
            "X-Ca-Stage": "RELEASE",
            "X-Ca-Nonce": xcanonce,
            "X-Ca-Signature-Headers": "X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Stage",
            "x-ca-signature-method": "HmacSHA256",
            "X-Ca-Signature": ""
        }
    else:
        headers = {
            "w-ca-token": token,
            "X-Ca-Key": "203773710",
            "X-Ca-Stage": "RELEASE",
            "X-Ca-Nonce": xcanonce,
            "X-Ca-Signature-Headers": "X-Ca-Key,X-Ca-Nonce,X-Ca-Signature-Method,X-Ca-Stage",
            "x-ca-signature-method": "HmacSHA256",
            "X-Ca-Signature": ""
        }
    # 参与签名的参数
    date = '';
    textToSign = "";
    textToSign += method + "\n";
    textToSign += "*/*" + "\n";
    textToSign += date + "\n";
    textToSign += "application/x-www-form-urlencoded; charset=UTF-8" + "\n";
    textToSign += date + "\n";
    textToSign += "X-Ca-Key:203773710" + "\n";
    textToSign += "X-Ca-Nonce:" + xcanonce + "\n";
    textToSign += "X-Ca-Signature-Method:HmacSHA256" + "\n";
    textToSign += "X-Ca-Stage:RELEASE" + "\n";
    textToSign += path;
    # 进行签名
    signature = base64.b64encode(
        hmac.new("jso3vuoso9ie85fzeyymwnyrinozr2vr".encode('utf-8'), textToSign.encode('utf-8'),
                 digestmod=hashlib.sha256).digest()).decode("utf-8")
    # 把签名放进headers
    headers['X-Ca-Signature'] = signature
    headers[
        'user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'
    headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    return headers


def encrypt(content, secret):
    from Crypto.Cipher import AES
    signature = hashlib.sha1(secret.encode()).digest()
    signature = hashlib.sha1(signature).digest()
    secret = ''.join(['%02x' % i for i in signature]).upper()[:32]
    cryptor = AES.new(bytes.fromhex(secret), AES.MODE_ECB)
    padding_value = str.encode(content + (16 - len(content) % 16) * chr(16 - len(content) % 16))
    ciphertext = cryptor.encrypt(padding_value)
    return ''.join(['%02x' % i for i in ciphertext]).upper()


def catchnowfields():
    appkey = "84f5b87827614f8180fdcdd572a2a77d"
    appSecret = "8cda9ed2f9b140dda6027485358fa5e9"
    params = {'status': 5, 'customers': '3'}
    sign = hashlib.new('md5', json.dumps(params).encode(encoding='UTF-8')).hexdigest()
    curtime = str(int(time.time()))
    checksum = encrypt(appkey + sign + str(curtime), appSecret)
    headers = {'Content-Type': 'application/json', 'ur-appkey': appkey, 'ur-sign': sign, 'ur-curtime': curtime,
               'ur-checksum': checksum}
    res=requests.post("https://huke.163.com/openapi/customer/fields",headers=headers,verify=False)
    print(res.text)

if __name__=='__main__':
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ODYyMjYzLWU4OGItNDcwNy1hNjhkLTlmNzkxMWQ3ZmE3ZiIsImp0aSI6IjYwNjg2Y2ViOWQ5NzIifQ.eyJpc3MiOiJodHRwczpcL1wvYXBpLmxhd3RpbWUuY24iLCJhdWQiOiJodHRwczpcL1wvbGF3dGltZS5jbiIsImp0aSI6IjYwNjg2Y2ViOWQ5NzIiLCJpYXQiOjE2MTc0NTYzNjMsImV4cCI6MTYxODA2MTE2MywidWlkIjoiNjA2NzYyIn0.44MKR7J5Lgz-EfuF9lsoNAmRsudOJ0rO3vy_NmAKVvRmbx7aNoZ_xhklWjaGB4eHpaTxal4pufE6yKorALMpsET59LC_33n_faLNeZLQ1FHjOxBpdM4QY1rpdCMRSywADbowcHcSElMfd5gbQk1SBTZpTqRiDDH3-ZvQPXxSD539-1NRcidcUt7ltX7YAoiMu6pICJQv8CVACFeuu_tJgf9FOtaAEJxV1PCx5oPUAghN32AzsYFqaPS-xyl4CobuBDFFAGAmftXyb8pcWmSnRdyV7FJnV_Bs_bsy_YTy5mZB06wUYtagyZdAl7mRtDihqZvNbDhMaff0Fm5EVWLVug'
    sessionkey = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjgzNzUyMzQyLWY2NmUtNTU2Mi1jODhnLTdkZjg4OTEwZG5mMSIsImp0aSI6IjYwNTg4Y2Y0NmNlZWQifQ.eyJpc3MiOiJodHRwczpcL1wvYXBpLmZpbmRsYXcuY24iLCJhdWQiOiJodHRwOlwvXC9maW5kbGF3LmNuIiwianRpIjoiNjA1ODhjZjQ2Y2VlZCIsImlhdCI6MTYxNjQxNTk4OCwiZXhwIjoxNjE3MDIwNzg4LCJ1aWQiOiI3MjU2NzQifQ.cVxQWx1W7k1wB-d8cecOAYx-sBWk1rSwVlj1hOaltKuep-urRhA2NOv5xPcZTRHJpFQQfaYYUFy4ATqf7QcauChjfBg51N8QxyL2Cj3zrL3N6spKIGweDpAb6acN-RymTKtUEA3rvW_3U5q_rlinBLnHrmow7MH1qnWiJaRi2xfYtOcbr3cPb8AEd_C_j5CQKOGxJBLRklM8Q5RvNOiB-iPutJUE29abgelsGWHfheV9boo-ppH5hCTSOV0jeszbAQsD-wygGMCQDFZMe6n4DJneOK5NtC0QsVfkUJ9mUbb0LDzpSgIp_3LXiLOM9RWJext3pnld4Mc7s63N6_7OzQ'
    b2 = '1898b698d220288350347fcbe4c8bf45581ef1b'
    headers = {'cookie': 'b2=' + b2,
               'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'}
    client = httpx.Client(http2=True, verify=False)
    a = ""
    print("位置" if(a=="") else a)