#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
from lib.poc.axfr_client import zone_transfer
import lib.config as conf


async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'domain' and port != 53:
        return
    try:
        domains = []
        for item in conf.dns_zone_transfer_domains.split('\n'):
            if item.strip():
                domains.append(item.strip())

        for d in domains:
            r = await asyncio.wait_for(zone_transfer(ip, port, d), 5)
            if r[0]:
                ret = {
                        'alert_group': 'DNS Zone Transfer',
                        'affects': '%s:%s' % (ip, port),
                        'details': u'通过域传送漏洞可导致内部所有域名泄露，不允许开放axfr功能\n'
                                   u'Run dig @{} {} axfr for details'.format(ip, d),
                        }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    import wx
    app = wx.App()
    conf.load_config()
    scan = do_scan('easypen-test.lijiejie.com', 53, 'domain', True, task_msg={})
    run_plugin_test(scan)
