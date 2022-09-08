#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    target = "{}://{}:{}/master/state.json".format(service, ip, port)
    help_info = "{}://{}:{}/help".format(service, ip, port)
    try:

        r = await http_client(ip, port).get(target, timeout=20)
        keys = r.json().keys()
        if r.status_code == 200 and "activated_slaves" in keys and "unreachable_slaves" in keys and \
                "leader_info" in keys:
            ret = {
                "alert_group": "Mesos API Unauthorized Access",
                "affects": target,
                "details": u"Mesos 未授权访问, 可操作机器上线下线及获取日志等，具体API可以访问: {}".format(help_info)
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 5050, 'mesos', True, {})
    run_plugin_test(scan)
