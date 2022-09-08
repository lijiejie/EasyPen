#!/usr/bin/evn python3
# coding=utf-8

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if port != 2375:
        return

    url = 'http://{}:{}/containers/json'.format(ip, port)
    try:
        r = await http_client(ip, port).get(url, timeout=10)
        if 'Command' in r.text and 'Status' in r.text and 'Created' in r.text:
            ret = {
                'alert_group': 'Docker Remote API',
                'affects': 'http://%s:%s' % (ip, port),
                'details': 'Docker Remote API  http://%s:%s/containers/json' % (ip, port)
            }
            return ret 

        r = await http_client(ip, port).get('http://{}:{}/'.format(ip, port), timeout=10)
        if '{"message":"page not found"}' in r.text:
            ret = {
                'alert_group': 'docker_remote_api',
                'affects': 'http://%s:%s' % (ip, port),
                'details': u'通过Docker API可查看，修改，或者在容器内执行命令,该端口不允许对外开放，'
                           u'仅支持绑定127.0.0.1或者使用iptables限制访问来源\n'
                           u'Docker Remote API  http://%s:%s' % (ip, port)
            }
            return ret 

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2375, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
