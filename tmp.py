#!/usr/bin/python
# coding:utf-8

from pocsuite.api.cannon import Cannon
info = {"pocname": "_170826_Zabbix_303_SQL_Injection",
        "pocstring": open("./_170826_Zabbix_303_SQL_Injection.py").read(),
        "mode": "verify"}

target = "http://89.239.138.140"
invoker = Cannon(target, info)
result = invoker.run()
print result
