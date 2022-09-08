#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'http':
        return
    try:
        url = 'http://%s:%s/index.php' % (ip, port)
        data = "request=&name=Admin&password=zabbix&autologin=1&enter=Sign+in"

        r = await http_client(ip, port).post(url, data=data, timeout=20)

        if r.status_code == 200:
            m = re.search("Connected as 'Admin'", r.text)
            if m:
                ret = {
                    'alert_group': 'Zabbix SQL Injection',
                    'affects': 'http://%s:%s/index.php' % (ip, port),
                    'details': 'Zabbix Default Account Authentication :\n\n%s    Admin / zabbix' % url
                }
                return ret
    except Exception as e:
        debug(e)
