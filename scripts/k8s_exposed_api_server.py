#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


async def list_api(ip, port, url):
    try:
        r = await http_client(ip, port).get(url + '/api/v1/namespaces', timeout=20)
        json_data = r.json()
        return [json_data['items'][i]['metadata']['selfLink'] for i in range(len(json_data['items']))]
    except Exception as e:
        pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        base_url = "{}://{}:{}".format(service, ip, port)
        r = await http_client(ip, port).get(base_url, timeout=20)
        if r.text.find('apis/autoscaling') > 0:
            r = await http_client(ip, port).get(base_url + '/api/v1', timeout=20)
            if r.text.find('"kind": "APIResourceList"') > 0:
                ret = {
                    'alert_group': 'K8s API Server Exposed',
                    'affects': '%s/api/v1' % base_url,
                    'details': 'With %s/api/v1/, can access apis\n'
                               '%s' % (base_url, '\n'.join(await list_api(ip, port, base_url))),
                }
                return ret
    except Exception as e:
        debug(e)
        

if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 6443, 'https', True, {})
    run_plugin_test(scan)
