#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
# author = 'ifk'
# Refer http://www.wooyun.org/bugs/wooyun-2010-0101152

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '%s://%s:%s' % (service, ip, port) + '/security-scan.txt'

    try:
        r = await http_client(ip, port).put(url, data="202cb962ac59075b964b07152d234b20", timeout=20)
        if r.status_code in [200, 201, 204]:
            r = await http_client(ip, port).get(url, timeout=20)
            if r.status_code == 200 and r.text.startswith('202cb962ac59075b964b07152d234b20'):
                ret = {
                    'alert_group': 'WebDAV PUT File',
                    'affects': '%s://%s:%s' % (service, ip, port),
                    'details': u'可直接通过PUT方法上传一个文件至服务器上, 如上传一个webshell则可获取系统权限\n'
                               u'PUT File Vulnerability\n\n' + url
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8082, 'http', True, task_msg={})
    run_plugin_test(scan)
