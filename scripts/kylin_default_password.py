#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
from itertools import product


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    usernames = ['ADMIN', 'admin']
    passwords = ["KYLIN", "kylin", "123456"]

    path = "/kylin/api/user/authentication"

    try:
        url = "{}://{}:{}{}".format(service, ip, port, path)
        for auth in product(usernames, passwords):
            r = await http_client(ip, port).post(url, auth=auth, json={}, timeout=20)
            if r.status_code == 200 and r.json()["userDetails"]["username"] == auth[0]:
                ret = {
                    'alert_group': 'Weak Password[kylin]',
                    'affects': '{}:{}'.format(ip, port),
                    'details': "Kylin has default/weak password: {}/{}, "
                               "version < 3.0.2 can execute system command".format(auth[0], auth[1])
                }
                return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 47070, 'http', True, {})
    run_plugin_test(scan)
