#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
import etcd3


def list_keys(ip, port):
    etcd = etcd3.client(host=ip, port=port)
    count = 0
    all_keys = []
    for item in etcd.get_prefix('/'):
        count += 1
        if count < 10:
            all_keys.append(item[1].key.decode())

    return count, all_keys


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        base_url = "{}://{}:{}".format(service, ip, port)
        target = base_url + "/v2/keys/?recursive=true"
        r = await http_client(ip, port).get(target, timeout=20)
        if r.text.find('{"action":"get"') >= 0:
            count, keys = list_keys(ip, port)
            ret = {
                'alert_group': 'K8s Etcd Unauthorized Access',
                'affects': '%s/v2/keys' % base_url,
                'details': 'k8s etcd unauthorized access: %s \nFound %s keys, first 10 keys are:\n'
                           '%s' % (base_url, count, "\n".join(keys)),
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 2379, 'http', True, {})
    run_plugin_test(scan)
