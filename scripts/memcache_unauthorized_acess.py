#!/usr/bin/python

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):

    if service not in ['memcache', 'memcached'] and port != 11211:
        return

    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b"stats\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1000), 5)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
        if b"connection_structures" in data:
            ret = {
                'alert_group': 'Weak Password[memcached]',
                'affects': 'memcache://%s:%s' % (ip, port),
                'details': 'memcached [unauthorized access]: %s:%s' % (ip, port)
            }
            return ret

    except Exception as e:
        logger.error('Memcached crack exception: %s' % str(e))
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 31472, 'memcache', False, task_msg={})
    run_plugin_test(scan)
