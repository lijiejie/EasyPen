#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    login_url = "{}://{}:{}/login.do".format(service, ip, port)

    try:
        for pwd in ['admin', '123456']:
            r = await http_client(ip, port).post(login_url, data={"userCode": "admin", "password": pwd}, timeout=10)

            if r.status_code in [301, 302] and r.headers.get("Set-Cookie", "").find("login_id=admin") >= 0:
                ret = {
                    'alert_group': '[Weak Password]Bistoury',
                    'affects': login_url,
                    'details': u'使用了弱口令的Bistoury, 可通过弱口令登录应用进而获取有权限机器的密钥与敏感配置文伯上'
                               u'请修改弱口令 admin/{}'.format(pwd)
                }
                return ret
    except Exception as e:
        debug(e)

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
