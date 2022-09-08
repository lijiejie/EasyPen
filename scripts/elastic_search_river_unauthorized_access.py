#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'wap-wsp' and port != 9200:
        return
    try:
        url = 'http://%s:%s/_river/_search' % (ip, port)
        r = await http_client(ip, port).get(url, timeout=20)

        if r.status_code == 200 and '_river' in r.text and 'type' in r.text:
            ret = {
                'alert_group': 'ES river unauthorized access',
                'affects': 'http://%s:%s' % (ip, port),
                'details': u'ES river 可未授权访问，信息泄露: %s' % url
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9200, 'http', True, task_msg={})
    run_plugin_test(scan)
