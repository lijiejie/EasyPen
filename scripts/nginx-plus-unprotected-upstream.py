from lib.poc.dummy import *
import re


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '{}://{}:{}/upstream_conf?upstream=backend'.format(service, ip, port)

        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 200 and 'server' in r.text:
            m = re.search(r'(server\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,4};\s#\sid=\d+)', r.text)
            if m:
                ret = {
                    'alert_group': 'NGINX+ unprotected Upstream HTTP interface',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': '{}\nNGINX+ unprotected Upstream HTTP interface.'.format(url)
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
