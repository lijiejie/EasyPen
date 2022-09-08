#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/manage' % (service, ip, port)
        r = await http_client(ip, port).get(url, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=10)
        if r.status_code == 200 and 'pluginManager' in r.text:
            ret = {
                'alert_group': 'Jenkins Command Execution',
                'affects': url,
                'details': u'通过Jenkins这个漏洞，可在系统上执行任意命令，造成入侵事件: ' + url
            }
            return ret
    except Exception as e:
        debug(e)

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, {})
    run_plugin_test(scan)
