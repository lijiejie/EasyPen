#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output
import re
import os
import platform
import time
import lib.config as conf


cwd = os.path.split(os.path.abspath(__file__))[0]
dict_dir = os.path.abspath(os.path.join(cwd, '../../config/dict'))


"""
Ncrack support services:

Modules: SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP, 
         Redis, PostgreSQL, MQTT, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM
"""


async def do_scan(ip, port, service, is_http, task_msg):
    return
    if platform.system() != 'Windows' or not conf.ncrack_found:    # windows or medusa not found
        return

    if service == 'ms-wbt-server' or port == 3389:
        service = 'rdp'
    elif service in ['microsoft-ds', 'netbios-ssn'] or port == 445:
        service = 'smb'
    elif service == 'ms-sql-s':
        service = 'mssql'
    elif service == 'postgresql':
        service = 'psql'
    elif service in ['sugon', 'iDRAC']:
        service = 'ssh'
    elif service == 'cassandra-native':
        service = 'cassandra'

    # SNMP not supported
    if service not in ['rdp', 'smb', 'ssh', 'ftp', 'telnet', 'mssql', 'mysql', 'psql', 'cassandra',
                       'telnet', 'vnc']:
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

        ncrack_path = 'ncrack'
        # debug
        # ncrack_path = r''
        if user and password:
            format_str = '%s %s://%s:%s --user %s --pass %s'
            cmd = format_str % (ncrack_path, service, ip, port, user, password)
        else:
            out_file_path = 'tools/ncrack/crack_%s_%s_%s_%s.xml' % (service, ip, port, round(random.random(), 3))

            path = os.path.join(dict_dir, '%s_password.txt' % service)
            if os.path.exists(path):
                pwd_file_path = path
            else:
                pwd_file_path = os.path.join(dict_dir, 'password.txt')

            format_str = '%s -U %s -P %s -f %s://%s:%s -oX %s'
            cmd = format_str % (ncrack_path,
                                os.path.join(dict_dir, '%s_user.txt' % service),
                                pwd_file_path,
                                service, ip, port,
                                os.path.abspath(os.path.join(conf.root_path, out_file_path))
                                )
        logger.info(cmd)
        cmd_out = await check_cmd_output(cmd, 180)
        print(cmd_out)
        return
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
