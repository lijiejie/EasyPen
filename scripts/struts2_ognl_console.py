#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/struts/webconsole.html' % (service, ip, port)
        r = await http_client(ip, port).get(url, timeout=20)

        if r.status_code == 200 and "Welcome to the OGNL console" in r.text:
            ret = {
                'alert_group': 'Struts2 OGNL Console',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': 'Struts2 OGNL Console\n\n' + url
            }
            return ret
    except Exception as e:
        debug(e)