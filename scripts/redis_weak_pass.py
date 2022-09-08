#!/usr/bin/python

from lib.poc.dummy import *
import aioredis
import os


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() != 'redis' and port != 6379:
        return

    pwd_list = ['']
    cwd = os.path.split(__file__)[0]
    with open(os.path.join(cwd, '../config/dict/redis_password.txt')) as pwdFile:
        for pwd in pwdFile.readlines():
            if pwd.strip():
                pwd_list.append(pwd.strip())

    for pwd in pwd_list:
        try:
            conn = await aioredis.from_url("redis://%s" % ip, port=port, password=pwd)
            dir = await conn.config_get('dir')
            dir = dir['dir']
            dbfilename = await conn.config_get('dbfilename')
            dbfilename = dbfilename['dbfilename']
            if dir.find('/.ssh') >= 0:
                al_group = 'Weak Password[Redis Hacked]'
                details = "%s:%s redis unauthorized access [password is %s]. " \
                          "Might be hacked, path was set to [%s/%s]" % (ip, port, repr(pwd), dir, dbfilename)
            else:
                al_group = 'Weak Password[Redis]'
                details = "%s:%s redis unauthorized access [password is %s]. " % (ip, port, repr(pwd))
            ret = {
                'alert_group': al_group,
                'affects': 'redis://%s:%s' % (ip, port),
                'details': details
            }
            del conn
            return ret
        except aioredis.exceptions.AuthenticationError as e:
            pass
        except aioredis.exceptions.ConnectionError as e:
            break
        except Exception as e:
            debug(e)
            break


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 6379, 'redis', False, task_msg={})
    run_plugin_test(scan)
