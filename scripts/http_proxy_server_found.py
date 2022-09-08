#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *
import dns.asyncresolver


if __name__ == '__main__':
    GLOBAL_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' \
                        '(KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        if is_ip_addr(ip):
            if is_intranet(ip) and False:
                return
        else:
            answers = await dns.asyncresolver.resolve(ip, "A")
            if False and is_intranet(answers[0].address):
                return
    except Exception as e:
        return

    exclude_ips = []

    if ip in exclude_ips:
        return

    target_url = "http://browserkernel.baidu.com/newpac31/videoproxy.conf.txt"
    proxy = "http://{}:{}".format(ip, port)
    try:

        async with httpx.AsyncClient(verify=False, proxies=proxy) as client:
            r = await client.get(target_url, headers={"User-Agent": GLOBAL_USER_AGENT}, timeout=20)

        if r.status_code == 200 and (r.text.find("cloudnproxy.baidu.com:443") >= 0 or
                                     r.text.find("thumbnail10.baidupcs.com") >= 0):
            ret = {
                'alert_group': 'HTTP Proxy',
                'affects': "%s://%s:%s" % (service, ip, port),
                'details': u"未认证的HTTP代理，可能遭黑客利用访问内网资源，"
                           u"造成内网渗透 [Unauthorized HTTP Proxy FOUND] %s:%s" % (ip, port)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('browserkernel.baidu.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
