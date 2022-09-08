#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    url = '%s://%s:%s' % (service, ip, port)
    url += "/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=es_6_0"
    try:

        r = await http_client(ip, port).get(url, timeout=20)
        if r.status_code == 200 and 'es_6_0' in r.json():
            ret = {
                'alert_group': 'ES Console LFI',
                'affects': url,
                'details': u"通过kibana的console插件，可执行本地的任意js文件，如有条件上传js的话，"
                           u"可导致本地任意命令执行，验证方式：" + "\n\n" + url +
                           ' \n\nFound text [es_6_0]'
            }
            return ret
    except json.decoder.JSONDecodeError as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8012, 'http', True, task_msg={})
    run_plugin_test(scan)
