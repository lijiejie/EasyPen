#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 2181 and not service.lower().startswith('zookeeper'):
        return

    # if is_intranet(ip):    # do not scan intranet IPs
    #     return

    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b"envi")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1000), 5)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

        if b"Environment" in data:
            msg = "[zookeeper unauthorized access]  zookeeper://%s:%s" % (ip, port)
            ret = {
                'alert_group': 'Zookeeper Unauthorized Access',
                'affects': 'zookeeper://%s:%s' % (ip, port),
                'details': msg
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2181, 'zookeeper', False, task_msg={})
    run_plugin_test(scan)
