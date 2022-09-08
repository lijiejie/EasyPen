#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/script' % (service, ip, port)
        r = await http_client(ip, port).get(url, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=10)
        if r.text.find('println(Jenkins.instance.pluginManager.plugins)') > 0:
            ret = {
                'alert_group': 'Jenkins Script Console RCE',
                'affects': url,
                'details': 'Jenkins Script Console Code Execution: ' + url
            }
            return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, {})
    run_plugin_test(scan)
