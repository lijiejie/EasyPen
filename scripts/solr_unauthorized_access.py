#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        base_url = '%s://%s:%s' % (service, ip, port)
        url = base_url + '/solr/admin/info/system?wt=json'

        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 200 and 'solr_home' in r.text:
            ret = {
                'alert_group': 'Solr Unauthorized Access',
                'affects': base_url,
                'details': 'Solr Unauthorized Access:\n\n' + url
            }
            return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
