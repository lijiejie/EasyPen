#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import ssl


if __name__ == '__main__':
    GLOBAL_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                        '(KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    #  payload = "GET /newpac31/videoproxy.conf.txt HTTP/1.1\r\n" + \
    payload = "GET :@browserkernel.baidu.com/newpac31/videoproxy.conf.txt HTTP/1.1\r\n" + \
              "Host: {}\r\n".format(ip) + \
              "User-Agent: " + GLOBAL_USER_AGENT + "\r\n" + \
              "Connection: close\r\n\r\n"
    try:
        if service == 'https':
            ssl_context = ssl._create_unverified_context()
            reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
        else:
            reader, writer = await asyncio.open_connection(ip, port)
        writer.write(payload.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2000), 6)
        writer.close()
        try:
            await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

        if data.decode().find("HOSTMATCH#mbd.baidu.com#DIRECT") >= 0:
            ret = {
                'alert_group': 'HTTP Proxy Misconfiguration',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': 'HTTP Server run as proxy, \n'
                           'hackers may use this Proxy bypass firewall to access enterprise network\n'
                           'This is extremely dangerous\n'
                           'GET :@browserkernel.baidu.com/newpac31/videoproxy.conf.txt HTTP/1.1\r\n'
                           'Host: {}\r\n'.format(ip)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('browserkernel.baidu.com', 443, 'https', True, task_msg={})
    run_plugin_test(scan)
