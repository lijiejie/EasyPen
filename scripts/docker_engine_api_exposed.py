from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        if port not in [2375, 2376]:
            return
        url = '{}://{}:{}/info'.format(service, ip, port)
        r = await http_client(ip, port).get(url, timeout=10)

        if r.status_code == 200 and 'Content-Type' in r.headers and 'application' in r.headers.get('Content-Type') \
                and 'ContainersRunning' in r.text and 'ContainersPaused' in r.text:
            ret = {
                'alert_group': 'Docker Engine API Exposed',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': '{}\nthe Docker Engine API is publicly accessible'.format(url)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2375, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
