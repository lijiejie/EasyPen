#!/usr/bin/env python
# coding=utf-8


from lib.poc.dummy import *


def all_repo_belongs_internet(repo):
    return all([i.startswith("knative") for i in repo])


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 5001 and service.find('Docker Registry') < 0:
        return

    try:
        url = "{}://{}:{}/v2/_catalog?n=10".format(service, ip, port)
        r = await http_client(ip, port).get(url, timeout=10)

        if "Docker-Distribution-Api-Version" in r.headers and "repositories" in r.text:
            if not all_repo_belongs_internet(r.json()['repositories']):
                ret = {
                    'alert_group': 'docker register unauth',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': u'docker register 未授权访问， 受影响的repo:\r\n{}'.format(
                        "\n".join(r.json()['repositories']))
                }
                return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 5001, 'HTTP', True, task_msg={})
    run_plugin_test(scan)


