#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup as bs
from lib.poc.dummy import *

PASSWORD = ['123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567',
            '123123', 'abc123', '666666']


async def get_xsrf(ip, port, url):
    try:
        r = await http_client(ip, port).get(url, timeout=20)
        soup = bs(r.text, 'html.parser')
        inputs = soup.find_all('input')
        for inp in inputs:
            if 'name' in inp.attrs and inp['name'] == '_xsrf':
                return inp['value']
    except Exception as e:
        pass


async def post_to_check(ip, port, url):
    try:
        xsrf = await get_xsrf(ip, port, url)
        if not xsrf:
            return

        for passwd in PASSWORD:
            data = {'_xsrf': xsrf, 'password': passwd.strip()}
            try:
                r = await http_client(ip, port).post(url, data=data, headers={"Cookie": "_xsrf=" + xsrf}, timeout=20)
                if r.status_code == 302 and r.headers.get('location', ''):
                    msg = '[+] Found Password:  [{}]  @ {}'.format(passwd, url)
                    return msg
            except Exception as e:
                pass
    except Exception as e:
        pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        target = '{}://{}:{}{}'.format(service, ip, port, '/login?next=%2Ftree%3F')

        r = await http_client(ip, port).get(target, timeout=20)
        if "<title>Jupyter Notebook</title>" not in r.text:
            return

        result = await post_to_check(ip, port, target)
        if result is not None:
            ret = {
                'alert_group': 'Jupyter Notebook Weak Password',
                'affects': '%s://%s:%s' % (service, ip, port),
                'details': result
            }
            return ret

    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8889, 'http', True, {})
    run_plugin_test(scan)
