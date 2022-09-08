#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    site = '{}://{}:{}'.format(service, ip, port)

    r = await http_client(ip, port).get(site + '/zh-CN/404_page', timeout=10)
    if r.text.find('was not found. - Splunk</title>') < 0:
        return

    for pwd in ['changeme', 'admin', '123456', 'admin123456']:
        try:
            data = {'cval': '123456', 'username': 'admin', 'password': pwd}
            r = await http_client(ip, port).post(site + '/zh-CN/account/login', data=data, timeout=10)
            if '{"status":0}' in r.text:
                details = 'Splunk [{}] WeakPass: admin:{}'.format(site, pwd)
                ret = {
                    'alert_group': 'Splunk Weak Password',
                    'affects': '%s' % site,
                    'details': details
                }

                return ret
        except Exception as e:
            debug(e)
            return ""

    return {'alert_group': 'Splunk Admin', 'affects': '%s' % site, 'details': 'Splunk Admin: {}'.format(site)}


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8000, 'https', True, task_msg={})
    run_plugin_test(scan)
