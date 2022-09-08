from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 2345:
        return

    try:
        payload = '{"method":"RPCServer.SetApiVersion","params":[{"APIVersion":2}],"id":0}'
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(payload.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(200), 5)
        writer.close()
        try:
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
        if b'{"id":0,"result":{},"error":null}' in data:
            ret = {
                'alert_group': 'Golang Delve Debugger',
                'affects': 'socket://{}:{}'.format(ip, port),
                'details': 'Delve Debugger port is publicly accessible'
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2345, 'dlv', False, task_msg={})
    run_plugin_test(scan)
