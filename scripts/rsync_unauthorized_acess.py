#!/usr/bin/python

from lib.poc.dummy import *
from lib.poc.process import check_cmd_output


async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'rsync' and port != 873:
        return
    try:
        rsync_path = get_exe_path('rsync')
        cmd = '%s %s:: --timeout=10 --contimeout=10 --port=%s --password-file=/dev/null' % \
              (rsync_path, ip, port)
        ret = await check_cmd_output(cmd, 10)
        if not ret:
            return
        details = 'Rsync[no auth] list: %s' % ', '.join(ret.split())
        if details.find('Welcome, to, use, the, rsync, services!, Current, Server, IP:') >= 0:
            return
        else:
            details = details[:250]
            file_result = []
            for _file in ret.split():
                try:
                    cmd = '%s %s::%s --timeout=10 --contimeout=10 --port=%s --password-file=/dev/null' % \
                          (rsync_path, ip, _file, port)
                    ret = await check_cmd_output(cmd, 30)
                    if not ret:
                        file_result.append(False)
                    else:
                        file_result.append(True)
                except Exception:
                    pass
            if any(file_result):
                ret = {
                    'alert_group': 'rsync Weak Password',
                    'affects': 'rsync://%s:%s' % (ip, port),
                    'details': details
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    print(do_scan("easypen-test.lijiejie.com", 873, "rsync", False, {}))
