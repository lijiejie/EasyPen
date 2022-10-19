#!/usr/bin/env python3
# coding=utf-8

import os
from lib.poc.dummy import *
from lib.poc.process import check_cmd_output


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower().find("rmi") < 0 and service.lower().find("jmx") < 0:
        return

    if is_intranet(ip):
        return
    
    jmxquery_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jarfile/JMXQuery-0.1.8.jar")
    url = "service:jmx:rmi:///jndi/rmi://{}:{}/jmxrmi".format(ip, port)
    try:
        cmd = 'java -jar "{jar}" -url {url} ' \
              '-q "java_lang_{{attribute}}_{{attributeKey}}<type={{type}}>==*:*/HeapMemoryUsage"'.format(
                jar=jmxquery_path, url=url)
        p = await check_cmd_output(cmd, 10, shell=True)
        if p.find('java_lang_HeapMemoryUsage_committed') >= 0:
            ret = {
                'alert_group': 'jmx exposed',
                'affects': 'jmx://%s:%s' % (ip, port),
                'details': u"通过jmx的调试端口，可以配置mbeans, 用于在系统上执行任意命令，该接口推荐加认证后开放\n\n"
                           u"memory usage:{}".format(p)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9996, 'rmi', True, {})
    run_plugin_test(scan)
