#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 2049:
        return
    try:
        cmd = 'showmount -e {0}'.format(ip)
        data = await check_cmd_output(cmd, 6)
        if 'everyone' in data or ' *\n' in data:
            ret = {
                'alert_group': 'NFS Unauthorized Access',
                'affects': 'nfs://%s:%s' % (ip, port),
                'details': 'NFS UnAuthorized Access  %s\n%s' % (ip, data)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2049, 'nfs', False, task_msg={})
    run_plugin_test(scan)

