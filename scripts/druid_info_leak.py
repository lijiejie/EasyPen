#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    base_url = "{}://{}:{}".format(service, ip, port)
    endpoints = {
        "/druid/header.html": "Druid Monitor</a>",
        "/druid/basic.json": ["com.alibaba.druid.mock.MockDriver", "com.alibaba.druid.proxy.DruidDriver"]
    }

    for endpoint in endpoints:
        try:
            url = base_url + endpoint
            r = await http_client(ip, port).get(url, timeout=20)
            pattern = endpoints.get(endpoint)
            if isinstance(pattern, str) and r.text.find(pattern) > 0 or \
                    isinstance(pattern, list) and any([p in r.text for p in pattern]):
                ret = {
                    'alert_group': 'Druid Information Disclosure',
                    'affects': url,
                    'details': u"通过druid可查看SQL地址，请求资源等，造成信息泄露\n {}\n ".format(url)
                }
                return ret
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9200, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
