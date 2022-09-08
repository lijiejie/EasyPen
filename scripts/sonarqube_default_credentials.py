from lib.poc.dummy import *


async def test_auth(ip, port, url, username, password):
    data = {'login': username, 'password': password}
    r = await http_client(ip, port).post(url + '/api/authentication/login', data=data, timeout=20)
    if r.status_code == 200 and 'Set-Cookie' in r.headers:
        cookies = r.headers.get('Set-Cookie')
        if 'XSRF-TOKEN=' in cookies and 'JWT-SESSION=' in cookies:
            return True
    return False


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 9000:
        return

    url = '{}://{}:{}'.format(service, ip, port)
    try:
        r = await http_client(ip, port).get(url, timeout=20)
        if r.text.find('<meta name="application-name" content="SonarQube"/>') >= 0:
            if await test_auth(ip, port, url, 'admin', 'admin') and \
                    not await test_auth(ip, port, url, '4dmin', '4dmin') and \
                    await test_auth(ip, port, url, 'admin', 'admin'):
                ret = {
                    'alert_group': 'SonarQube Default Credentials',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': '{}/api/authentication/login\n{}\n'
                               'SonarQube default credentials.'.format(url, 'login=admin&password=admin')
                }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan("easypen-test.lijiejie.com", 9000, 'http', True, task_msg={})
    run_plugin_test(scan)
