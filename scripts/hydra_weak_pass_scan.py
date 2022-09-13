#!/usr/bin/env python 
# -*- coding: utf-8 -*- 

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output
import re
import tempfile
import os
import platform
import lib.config as conf


cwd = os.path.split(os.path.abspath(__file__))[0]
dict_dir = os.path.abspath(os.path.join(cwd, '../config/dict'))


def parse_result_hydra(tmp_file):
    try:
        if not os.path.exists(tmp_file):
            return
        ret = None
        for line in open(tmp_file, 'r').readlines():
            line = str(line).strip('\r\n')
            if not line:
                continue
            m = re.findall(r'host: (\S*).*login: (\S*).*password:(.*)', line)
            if m and m[0] and len(m[0]) == 3:
                username = m[0][1]
                password = m[0][2].strip()
                return line
            m = re.findall(r'host: (\S*).*password:(.*)', line)
            if m and m[0] and len(m[0]) == 2:
                password = m[0][1].strip()
                return line
        return ret
    except Exception as e:
        logger.error('parse_result_hydra.Exception %s' % str(e))


async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.hydra_path:
        return

    hydra_path = conf.hydra_path

    if service == 'ms-wbt-server' or port == 3389:
        service = 'rdp'
    elif service in ['microsoft-ds', 'netbios-ssn'] or port == 445:
        service = 'smb'
    elif service == 'ms-sql-s' or port == 1433:
        service = 'mssql'
    elif service == 'postgresql' or port == 5432:
        service = 'postgres'
    elif port == 22:
        service = 'ssh'
    elif port == 23:
        service = 'telnet'
    elif port == 161:
        service = 'snmp'
    elif service == 'unknown' and 5901 <= port <= 5906:
        service = 'vnc'

    """
    Supported services to be brute:
    ftp[s] mssql mysql postgres rdp redis sip smb snmp socks5 ssh telnet[s] vnc
    """
    if service not in ['ftp',  'mssql', 'mysql', 'postgres', 'rdp', 'smb', 'snmp',  'ssh', 'telnet', 'vnc']:
        return

    try:
        tmp_file = tempfile.mktemp()
        null_dev = 'NUL' if platform.system() == 'Windows' else '/dev/null'

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

        if service in ['vnc', 'snmp', 'redis']:
            params_of_user = ''
        else:
            params_of_user = '-L %s' % user_file_path

        cmd = '%s %s -P %s -t 4 -s %s -e r -f -o %s %s %s >%s 2>&1' % (
            hydra_path,
            params_of_user,
            passwd_file_path,
            port,
            tmp_file,
            ip,
            service,
            null_dev
        )

        logger.info(cmd)
        await check_cmd_output(cmd, conf.brute_task_timeout * 60 - 10)
        details = parse_result_hydra(tmp_file)
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        if not details:
            return

        logger.info(details)

        ret = {
            'alert_group': 'Weak Password[%s]' % service,
            'affects': '%s://%s:%s' % (service, ip, port),
            'details': details
        }
        return ret

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 3389, 'ms-wbt-server', False, task_msg={})
    run_plugin_test(scan)
