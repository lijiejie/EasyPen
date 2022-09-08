from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        target = "{}://{}:{}".format(service, ip, port)
        r = await http_client(ip, port).get(target, timeout=20)
        if r.status_code == 200 and "x-kong-proxy-latency" in r.headers and r.text.find('X-Kong-Upstream-Latency') > 0\
                or '"tagline":"Welcome to kong"' in r.text:
            ret = {
                'alert_group': 'Kong Gateway Admin Rest API',
                'affects': '{}'.format(target),
                'details': 'Kong Admin Rest API: {}'.format(target)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 443, 'https', True, {})
    run_plugin_test(scan)
