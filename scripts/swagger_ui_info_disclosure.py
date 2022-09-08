#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import dns.asyncresolver


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    try:
        if is_ip_addr(ip):
            if is_intranet(ip):
                return
        else:
            answers = await dns.asyncresolver.resolve(ip, "A")
            if is_intranet(answers[0].address):
                return
    except Exception as e:
        return

    target = '{}://{}:{}'.format(service, ip, port)
    try:
        r = await http_client(ip, port).get(target + '/swagger-resources')
        if r.status_code == 200 and r.json() != []:
            path = r.json()[0]["location"]
            r2 = await http_client(ip, port).get(target + path)
            if r2.status_code == 200:
                if r2.json()['paths']:
                    details = "\n".join(r2.json()['paths'])
                    ret = {
                        'alert_group': 'Swagger UI Information Disclosure',
                        'affects': target + path,
                        'details': 'Swagger UI Information Disclosure:\n{}'.format(details)
                    }
                    return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)

    try:
        for url in ['/v2/api-docs', '/swagger.json', '/v2/swagger.json']:
            r = await http_client(ip, port).get(target + url)
            if r.text.find('"swagger":"') > 0:
                ret = {
                    'alert_group': 'Swagger UI Information Disclosure',
                    'affects': target + url,
                    'details': 'Swagger UI API信息泄露'
                }
                return ret

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'http', True, task_msg={})
    run_plugin_test(scan)
