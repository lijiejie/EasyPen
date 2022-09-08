#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *

is_tomcat = False


async def auth_success(ip, port, url, auth):
    try:
        r = await http_client(ip, port).get(url, auth=auth, timeout=20)
        if r.status_code in [200, 301, 302]:
            if r.text.find("Tomcat Web Application Manager") >= 0:
                global is_tomcat
                is_tomcat = True
            return True
    except Exception as e:
        debug(e)


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/manager/html' % (service, ip, port)
        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 401:

            for auth in [('tomcat', 'tomcat'), ('admin', 'admin'), ('admin', 'tomcat'), ('tomcat', 'admin')]:
                if await auth_success(ip, port, url, auth) and \
                        not await auth_success(ip, port, url, ('bad-user', 'bad-password')):
                    global is_tomcat
                    ret = {
                        'alert_group': 'Tomcat Weak Password' if is_tomcat else 'Basic Auth Weak Pass',
                        'affects': url,
                        'details': 'Basic Auth Weak Password Found: \n\n'
                                   '%s   %s' % (url, auth)
                    }
                    return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
