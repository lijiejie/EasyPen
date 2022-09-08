#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    try:
        target = '{}://{}:{}'.format(service, ip, port)
        r = await http_client(ip, port).get(target, timeout=20)
        for key in r.headers.keys():
            if "rememberMe=" in r.headers[key]:
                ret = {
                    "alert_group": "shiro cookie",
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': 'shiro fingerprint cookie:\n {}'.format(r.headers[key])
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8043, 'https', True, task_msg={})
    run_plugin_test(scan)
