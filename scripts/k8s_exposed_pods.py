#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = "{}://{}:{}".format(service, ip, port)
        target = url + '/pods'
        r = await http_client(ip, port).get(target, timeout=20)
        if 'apiVersion' not in r.text:
            return
        json_data = r.json()
        keys = ['apiVersion', 'metadata', 'items']
        if json_data['kind'] == "PodList" and all([i in json_data.keys() for i in keys]):
            pods = [json_data['items'][i]['metadata']['selfLink'] for i in range(len(json_data['items']))]

            ret = {
                'alert_group': 'K8s Pods Unauthorized Access',
                'affects': '%s/pods' % url,
                'details': 'Access %s/pods, attackers can create pods, execute command or delete containers\n%s' % (
                    url, '\n'.join(pods)),
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)

if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 10255, 'http', True, {})
    run_plugin_test(scan)
    