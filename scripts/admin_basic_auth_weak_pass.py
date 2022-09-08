#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/admin/' % (service, ip, port)

        r = await http_client(ip, port).get(url, timeout=20.0)
        if r.status_code == 401:
            for auth in [('admin', 'admin'), ('admin', '123456'), ('guest', 'guest')]:
                response = await http_client(ip, port).get(url, auth=auth, timeout=20.0)
                if response.status_code == 200:
                    ret = {
                        'alert_group': 'Admin Page Weak Pass',
                        'affects': url,
                        'details': 'Admin Page Weak Password: \n'
                                   '%s    admin / admin' % url
                    }
                    if response.text.find('ActiveMQ Console') > 0:
                        ret['alert_group'] = 'Admin Page Weak Pass[ActiveMQ]'
                    return ret
    except Exception as e:
        debug(e)

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8161, 'http', True, task_msg={})
    run_plugin_test(scan)
