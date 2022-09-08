#!/usr/bin/env python
# coding=utf-8

"""
from: https://github.com/timwhitez/Frog-Auth/blob/1c7880738ec9f51f81c44454420004e4a745aed0/pocs/pocs.py#L248
"""
from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower().find("influxdb") < 0:
        return

    try:
        base_url = "http://{}:{}".format(ip, port)

        r = await http_client(ip, port).get(base_url + "/ping", timeout=10)
        if str(r.headers).lower().find('x-influxdb-version') > 0:

            r = await http_client(ip, port).get(base_url + "/query?q=show%20users", timeout=10)
            if 'columns' in r.text and 'user' in r.text:
                ret = {
                    'alert_group': 'Weak Password[InfluxDB]',
                    'affects': 'http://{}:{}'.format(ip, port),
                    'details': u'InfluxDb未授权访问，可泄露敏感信息。 \r\n'
                               u'修复方案： 在配置中修改auth-enabled = true',
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8086,
                   'InfluxDB http admin 1.0.0', True, {"service_product": "influxdb"})
    run_plugin_test(scan)
