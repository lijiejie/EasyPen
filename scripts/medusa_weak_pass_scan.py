#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output
import re
import os
import platform
import lib.config as conf


cwd = os.path.split(os.path.abspath(__file__))[0]
dict_dir = os.path.abspath(os.path.join(cwd, '../config/dict'))


async def do_scan(ip, port, service, is_http, task_msg):
    if platform.system() == 'Windows' or not conf.medusa_found:    # windows or medusa not found
        return

    if service == 'ms-wbt-server' or port == 445:
        service = 'smbnt'
    elif service == 'ms-wbt-server' or port == 3389:
        service = 'rdp'
    elif service == 'ms-sql-s':
        service = 'mssql'
    elif service == 'postgresql':
        service = 'postgres'
    elif service.lower() in ['sugon', 'idrac']:
        service = 'ssh'

    if service not in ['ftp', 'mssql', 'mysql', 'postgresql', 'smbnt', 'snmp', 'ssh', 'rdp', 'svn', 'telnet', 'vnc']:
        return

    try:
        user = password = None
        if 'details' in task_msg:
            ret = re.search(r'User: (\S+).*Password: (\S+)', task_msg['details'])
            if ret:
                try:
                    password = ret.group(2)
                    user = ret.group(1)
                except Exception as e:
                    pass

        medusa_path = get_exe_path('medusa')
        # debug
        # medusa_path = r''
        if user and password:
            format_str = '%s -h%s -u %s -p %s -M %s -n %s -ens'
            cmd = format_str % (medusa_path, ip, user, password, service, port)
        else:

            path = os.path.join(dict_dir, '%s_user.txt' % service)
            if os.path.exists(path):
                user_file_path = path
            else:
                user_file_path = os.path.join(dict_dir, 'ssh_user.txt')

            path = os.path.join(dict_dir, '%s_password.txt' % service)
            if os.path.exists(path):
                passwd_file_path = path
            else:
                passwd_file_path = os.path.join(dict_dir, 'password.txt')

            format_str = '%s -h%s -U %s -P %s -M %s -n %s -ens'
            cmd = format_str % (medusa_path, ip, user_file_path, passwd_file_path, service, port)
        logger.info(cmd)
        cmd_out = await check_cmd_output(cmd, 1200)
        if not cmd_out:
            return 
        ret = re.search('ACCOUNT FOUND:.*', cmd_out)
        if not ret:
            return

        details = ret.group(0) if ret else ''
        if details.find('[ERROR (0xFFFFFF:UNKNOWN_ERROR_CODE)]') >= 0:
            return

        if details.find('(0x0000') >= 0:
            return

        if details.find('Password:  [ERROR') >= 0:
            return

        if service == 'telnet' and details.find('User: root Password:  [SUCCESS]') > 0:    # false positive
            return

        logger.info(details)

        if details.find('User: ADMIN Password: ADMIN') > 0:
            service = 'sugon'
        elif details.find('User: root Password: calvin') > 0:
            service = 'iDRAC'

        ret = {
            'alert_group': 'Weak Password[%s]' % service,
            'affects': '%s://%s:%s' % (service, ip, port),
            'details': details
        }
        return ret

    except Exception as e:
        logger.info('[Medusa brute error %s] %s' % (ip, str(e)))
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 22, 'ssh', True, task_msg={})
    run_plugin_test(scan)
