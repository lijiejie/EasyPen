#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
import dns.asyncresolver


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() not in ['unknown', 'socks']:
        return

    target_url = "http://browserkernel.baidu.com/newpac31/videoproxy.conf.txt"

    try:
        # resolve to IP addr
        if not is_ip_addr(ip):
            try:
                answers = await dns.asyncresolver.resolve(ip, "A")
                ip = answers[0].address
            except Exception as e:
                return

        internet_ip = not is_intranet(ip)

        sock_proxy = "socks5://{}:{}".format(ip, port)

        async with httpx.AsyncClient(verify=False, proxies=sock_proxy) as client:
            r = await asyncio.wait_for(client.get(target_url, headers={"User-Agent": GLOBAL_USER_AGENT}), 20)

        code = r.status_code
        html = r.text
        if code == 200 and html.find("cloudnproxy.baidu.com:443") >= 0:
            ret = {
                'alert_group': 'SOCK5 Proxy [Internet]' if internet_ip else 'SOCKS Proxy [Intranet]',
                'affects': "SOCK5://%s:%s" % (ip, port),
                'details': "Unauthorized SOCK5 Proxy FOUND: %s:%s" % (ip, port)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 50023, 'socks', False, {})
    run_plugin_test(scan)
