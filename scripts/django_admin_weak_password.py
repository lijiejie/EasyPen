from lib.poc.dummy import *
import re
from itertools import product


async def valid_credentials(ip, port, url, username, password, csrf_token, cookies):
    try:
        data = {'csrfmiddlewaretoken': csrf_token, 'username': username, 'password': password}
        r = await http_client(ip, port).post(url, data=data, headers={'Cookie': cookies}, timeout=10)
        return r.status_code == 302
    except Exception as e:
        pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '{}://{}:{}'.format(service, ip, port)

    try:
        r = await http_client(ip, port).get(url + '/admin/', timeout=10)
        if r.status_code == 302 and 'Location' in r.headers:
            url = r.next_request.txt_domain
            r = await http_client(ip, port).get(url, timeout=10)

        if r.status_code == 200 and '<title>Log in | Django site admin</title>' in r.text:
            csrf_token = re.findall(r'<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', r.text)[0]
            cookies = r.headers.get('Set-Cookie')
            if cookies:
                cookies = cookies.split(';')[0]

            if csrf_token and cookies:
                if not await valid_credentials(ip, port, url, random_str(8), random_str(8), csrf_token, cookies):
                    for item in product(
                            ['admin', 'root',  'Admin'],
                            ['admin', 'root', 'Admin', '123456']):
                        if await valid_credentials(ip, port, url, item[0], item[1], csrf_token, cookies):
                            ret = {
                                'alert_group': 'Django Admin Weak Password',
                                'affects': '{}://{}:{}'.format(service, ip, port),
                                'details': 'Django_Admin_Weak_Password:\n\n'
                                           '{}://{}:{}/admin/\nUsername:{}, Password:{}\n'
                                           ''.format(service, ip, port, item[0], item[1])
                            }
                            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
