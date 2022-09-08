#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


def intra(host):
    if is_ip_addr(host) and is_intranet(host):
        return True
    if host.find("your_company_intra_domain") >= 0 or host.find("your_company_intra_domain2") >= 0:
        return True
    return False


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    endpoints = {
        "env": "systemProperties",
        "actuator/env": "systemProperties",
        "configprops": 'serverProperties',
        "jolokia": ["request", "config", '"agentId"', '"agentType"'],
        "actuator/configprops": 'serverProperties',
        "actuator/jolokia": ["request", "config", '"agentId"', '"agentType"']
    }
    if not intra(ip):
        endpoints.update({
            "beans": "dependencies",
            "mappings": ["bean\":\"resourceHandlerMapping"],
            "trace": ['info', 'method', 'timestamp', 'path'],
            "conditions": ["positiveMatches", "condition"],
            "actuator/beans": "dependencies",
            "actuator/mappings": ["bean\":\"resourceHandlerMapping"],
            "actuator/trace": ['info', 'method', 'timestamp', 'path'],
            "actuator/conditions": ["positiveMatches", "condition"],
            "metrics": ['processors', 'heap.committed', 'threads'],
            "actuator/metrics": ['jvm.memory.committed', 'process.files.max', 'process.start.time'],
        })

    founds = []
    for endpoint in endpoints:
        try:
            url = '{}://{}:{}/{}'.format(service, ip, port, endpoint)
            r = await http_client(ip, port).get(url, timeout=10)
            if r.status_code == 200:
                aim = endpoints.get(endpoint)
                if isinstance(aim, str) and r.text.find(aim) > 0 or \
                        isinstance(aim, list) and all([a in r.text for a in aim]):
                    founds.append(url)
        except Exception as e:
            debug(e)
    if founds:
        alert_group = 'Spring Boot Actuator'
        if any([url.endswith('env') or url.endswith('configprops') for url in founds]):
            alert_group += '[Critical]'
        ret = {
            'alert_group': alert_group,
            'affects': '{}://{}:{}'.format(service, ip, port),
            'details': '通过env配置，可导致命令执行, 服务器被入侵。 其他接口会导致信息泄露，需尽快修复, \n'
                       '受影响Endpoint:\n' + '\n'.join(founds) + '\n'
                       '参考: http://THIS_LINKS_HAS_BEEN_REMOVED#\n'
        }
        return ret

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 2985, 'http', True, task_msg={})
    run_plugin_test(scan)
