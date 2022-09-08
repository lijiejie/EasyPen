#!/usr/bin/env python 
# -*- coding: utf-8 -*- 

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'idrac':
        return

    if 'password' not in task_msg:
        return
    password = task_msg['password']

    try:
        r = await http_client(ip, port).post('https://%s/data/login' % ip,
                                             data='user=root&password=%s' % password, timeout=20)
        if r.text.find('<authResult>0</authResult>') > 0:
            details = '[iDRAC weak pass found] https://%s    root / %s' % (ip, password)
            ret = {
                'alert_group': 'iDRAC Weak Pass',
                'affects': 'https://%s:%s' % (ip, port),
                'details': details
            }
            return ret

        # be sure is unspur
        r = await http_client(ip, port).get('https://%s/index.html' % ip, timeout=20)

        if r.text.find('<img ng-src="img/inspur_logo.png" alt="" style="height:30px" />') > 0:
            # is inspur
            for user in ['root', 'admin']:
                data = {'WEBVAR_USERNAME': user, 'WEBVAR_PASSWORD': password}
                r = await http_client(ip, port).post('https://%s/rpc/WEBSES/create.asp' % ip, data=data, timeout=20)
                if r.text.find('HAPI_STATUS:0') > 0:
                    ret = {
                        'alert_group': 'iDRAC Weak Pass',
                        'affects': 'https://%s:%s' % (ip, port),
                        'details': '[inspur iDRAC weak pass found] https://%s   %s / %s' % (ip, user, password)
                    }
                    return ret

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 443, 'idrac', True, task_msg={'password': ''})
    run_plugin_test(scan)
