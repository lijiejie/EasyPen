#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    base_url = '{}://{}:{}'.format(service, ip, port)
    try:
        r = await http_client(ip, port).get(base_url + '/json/version', timeout=20)
        r = r.json()
        if 'Browser' in r and "Protocol-Version" in r:
            r2 = await http_client(ip, port).get(base_url + '/json', timeout=20)
            r2 = r2.json()
            if any(["webSocketDebuggerUrl" in i for i in r2]):
                ret = {
                    'alert_group': 'Node.js Debug Info',
                    'affects': base_url,
                    'details': 'url/json/version: \n{}\n url/json: {}'.format(r, r2)
                }
                return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9227, 'http', True, task_msg={})
    run_plugin_test(scan)
