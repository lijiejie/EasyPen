#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = "{}://{}:{}".format(service, ip, port)

    try:
        r = await http_client(ip, port).get(url, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)
        word = "<title>Kubernetes Dashboard</title>"
        if r.text.find(word) >= 0:
            ret = {
                'alert_group': 'k8s dashboard',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': u"Find {} in response\r\n"
                           u"DashBoard安全性未配置好的情况下, 可能导致整个集群被控制，必须配置强密码或者token登录".format(word)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, {})
    run_plugin_test(scan)
