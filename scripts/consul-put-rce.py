#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


async def deregister_consul(ip, port, check_id):
    try:
        url = 'http://{}:{}/v1/agent/check/deregister/{}'.format(ip, port, check_id)
        await http_client(ip, port).put(url, headers={'Content-Type': 'application/json'}, timeout=10)
    except Exception as e:
        pass


async def check_put_success(ip, port, url, url2):
    try:
        data = {
            "ID": "securityConsulCheck" + str(random.randint(10000, 999999)),
            "Name": "Memory utilization",
            "Notes": "Ensure we don't oversubscribe memory",
            "DeregisterCriticalServiceAfter": "90m",
            "Args": ["/usr/local/bin/check_mem.py"],
            "Shell": "/bin/bash",
            "HTTP": "https://example.com",
            "Method": "POST",
            "Header": {"x-foo": ["bar", "baz"]},
            "TCP": "example.com:22",
            "Interval": "10s",
            "TLSSkipVerify": True
        }

        await http_client(ip, port).put(url, json=data, timeout=10)
        r = await http_client(ip, port).get(url2, timeout=10)

        if data['ID'] in r.keys():
            return data['ID']
    except Exception as e:
        pass
    return False


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 8500:
        return
    try:
        url = 'http://{}:{}/v1/agent/check/register'.format(ip, port)
        url2 = 'http://{}:{}/v1/agent/checks'.format(ip, port)

        check_id = await check_put_success(ip, port, url, url2)
        if check_id:
            await deregister_consul(ip, port, check_id)
            ret = {
                'alert_group': 'Consul RCE',
                'affects': url,
                'details': u'Consul未配置认证，可注册一个check来执行命令\n'
                           u'https://www.consul.io/api/agent/check.html'
            }
            return ret
    except Exception as e:
        debug(e)

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8500, 'HashiCorp Consul agent', True, task_msg={})
    run_plugin_test(scan)
