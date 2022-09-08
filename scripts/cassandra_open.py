from lib.poc.dummy import *
import base64


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 9042:
        return
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        payload = base64.b64decode('BAAAAAUAAAAA')
        writer.write(payload)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), 5)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

        if b"CQL_VERSION" in data or b'Invalid or unsupported protocol version' in data:
            ret = {
                'alert_group': 'Apache Cassandra Unauthorized Access',
                'affects': '{}:{}'.format(ip, port),
                'details': 'socket://{}:{}\nCassandra service is exposed'.format(ip, port),
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9042, 'unknown', True, task_msg={})
    run_plugin_test(scan)
