#!/usr/bin/python

from lib.poc.dummy import *
import motor.motor_asyncio


async def do_scan(ip, port, service, is_http, task_msg):
    if service not in ['mongod', 'mongodb']:
        return

    try:
        client = motor.motor_asyncio.AsyncIOMotorClient(ip, port)
        ret = await client.list_database_names()
        details = '[MongoDB Unauthorized Access] database list: %s' % ret
        ret = {
            'alert_group': 'Mongodb Unauthorized Access',
            'affects': 'mongodb://%s:%s' % (ip, port),
            'details': details
        }
        return ret

    except Exception as e:
        if str(e).find('not authorized') < 0:
            logger.error('Mongodb crack exception: %s' % str(e))
            debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 27020, 'mongodb', False, task_msg={})
    run_plugin_test(scan)
