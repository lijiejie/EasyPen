#!/usr/bin/env python
# -*- coding: utf-8 -*-
import traceback
import requests
import subprocess
import logging
import httpx
import asyncio
from functools import wraps
import pprint
import re
import random
import string
import datetime
import json
import socksio
import ssl
import aiohttp.client_exceptions
import lib.config as conf


GLOBAL_USER_AGENT = conf.global_user_agent
GLOBAL_DEFAULT_HEADER = {'User-Agent': GLOBAL_USER_AGENT}
GLOBAL_PROXIES = conf.global_proxy_server if conf.global_proxy_server_enabled else None
all_pools = {}
all_dns_monitors = {}
logger = logging.getLogger("port_crack")


def http_client(ip, port):
    key = '%s:%s' % (ip, port)
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=40)
    if key not in all_pools:
        all_pools[key] = httpx.AsyncClient(headers=GLOBAL_DEFAULT_HEADER,
                                           proxies=GLOBAL_PROXIES, verify=False, limits=limits)
    return all_pools[key]


def do_nothing(e):
    pass


def debug_logger(e):
    try:
        # Use response.json() without try may raise JSONDecodeError
        ignored_errors = [httpx.PoolTimeout,
                          httpx.ConnectTimeout,
                          httpx.ReadTimeout,
                          httpx.ConnectError,
                          httpx.ReadError,
                          httpx.WriteError,
                          httpx.RemoteProtocolError,
                          json.decoder.JSONDecodeError,
                          socksio.exceptions.ProtocolError,
                          asyncio.exceptions.TimeoutError,
                          aiohttp.client_exceptions.ClientOSError,
                          ssl.SSLError,
                          ConnectionResetError,
                          ConnectionAbortedError,
                          TimeoutError,
                          OSError,
                          KeyError]
        if type(e) in ignored_errors:
            return
        logger.info(type(e))
        info = traceback.format_exc()
        logger.info(info)
    except Exception as e:
        pass


DEBUG_PLUGIN = conf.enable_plugin_debug
if DEBUG_PLUGIN:
    debug = debug_logger
else:
    debug = do_nothing


def do_not_block(f):
    @wraps(f)
    def wrapped_func(*args, **kwargs):
        loop = asyncio.get_running_loop()
        return loop.run_in_executor(None, lambda: f(*args, **kwargs))

    return wrapped_func


def random_str(count, digit=True):
    choices = string.ascii_lowercase
    if digit:
        choices += string.digits
    return ''.join(random.choices(choices, k=count))


def is_ip_addr(s):
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ret = pattern_ip.search(s)
    return True if ret else False


async def scan_func_do_nothing(ip, port, service, is_http, task_msg):
    pass


def http_scan(scan_func):
    """
        is_http check and replace service name to 'http' or 'https'
    """
    @wraps(scan_func)
    def wrapped_func(*args, **kwargs):
        service = args[2]
        is_http = args[3]

        if not is_http and service not in ['http', 'https']:
            return scan_func_do_nothing(*args, **kwargs)

        args = list(args)
        if service.find('https') >= 0 or service.find('ssl') >= 0:
            args[2] = 'https'
        else:
            args[2] = 'http'
        args = tuple(args)

        return scan_func(*args, **kwargs)

    return wrapped_func


async def print_scan_result(coroutine):
    r = await coroutine
    print("*" * 32 + "\nScan test returned:\n")
    if r:
        pprint.pprint(r)
    else:
        print(r)


def run_plugin_test(coroutine):
    loop = asyncio.get_event_loop()
    task = loop.create_task(print_scan_result(coroutine))
    loop.run_until_complete(task)


def is_http_service(service_name, is_http_flag):
    if service_name.lower().find("http") < 0 and is_http_flag is False:
        return False
    if service_name.lower().find("hadoop-ipc") >= 0:
        return False
    return True


def is_intranet(ip):
    ret = ip.split('.')
    if not len(ret) == 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 31:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False


def get_exe_path(_file):
    try:
        return subprocess.check_output('which %s' % _file, shell=True).strip().split()[0].decode()
    except Exception as e:
        logger.error('[ERROR] get_exe_path [%s]: %s' % (_file, str(e)))


class DNSMonitor(object):
    def __init__(self):
        self.DNS_POSTFIX = conf.dnslog_domain_postfix
        self.DNS_USER = conf.dnslog_user
        self.TOKEN = conf.dnslog_token
        self.DNS_API = conf.dnslog_api_server.rstrip('/') + '/api/group/dns/{dns_user}/{keyword}/?token={token}'
        self.WEB_API = conf.dnslog_api_server.rstrip('/') + '/api/web/{dns_user}/{keyword}/?token={token}'

        self.target = ''
        self.DOMAIN_POSTFIX = ''
        self.dns_to_check = {}
        self.web_to_check = {}
        self.http_client = None
        year, week_num, day = datetime.datetime.now().isocalendar()
        self.week_str = str(year)[-2:] + str(week_num)

    def set_target(self, target):
        self.target = target.replace('.', '-').replace('/', '-').replace(':', '-')
        self.DOMAIN_POSTFIX = '{}.{}.{}'.format(self.target, self.DNS_USER, self.DNS_POSTFIX)

    def add_checker(self, keyword, log_type='dns', alert_group='', details=''):
        if not self.target:
            self.set_target('http://scan-test.com')
        keyword = keyword.replace('.', '-').replace('/', '-').replace(':', '-') + '-' + self.week_str
        domain = keyword + '.' + self.DOMAIN_POSTFIX
        if log_type == 'dns':
            self.dns_to_check[keyword] = [alert_group, details]
        else:
            self.web_to_check[keyword] = [alert_group, details]
        return domain

    async def check(self, keyword='', log_type='dns'):
        if not self.http_client:
            self.http_client = httpx.AsyncClient(headers=GLOBAL_DEFAULT_HEADER, verify=False,
                                                 proxies=['http://your.proxy.server:8888',
                                                          'http://127.0.0.1:8080',
                                                          None][2])
        try:
            if log_type == 'web':
                url = self.WEB_API.format(dns_user=self.DNS_USER, keyword=keyword + '.' + self.target, token=self.TOKEN)
                r = await self.http_client.get(url, timeout=15)
                if r.status_code == 200 and 'True' == r.text:
                    return True
                else:
                    return False
            else:    # dns
                url = self.DNS_API.format(dns_user=self.DNS_USER, keyword=self.target, token=self.TOKEN)
                r = await self.http_client.get(url, timeout=15)
                if r.status_code == 200 and r.text.startswith('{"success": "true"'):
                    return r.json()['data']
                else:
                    return False
        except Exception as e:
            logger.error('DNSMonitor.check error: %s' % str(e))


def dns_monitor(ip, port):
    key = '%s:%s' % (ip, port)
    if key not in all_dns_monitors:
        all_dns_monitors[key] = DNSMonitor()

    return all_dns_monitors[key]


async def test_dns_log():
    monitor = dns_monitor('www.iqiyi.com', 443)
    monitor.set_target('https://www.iqiyi.com:443')

    domain1 = monitor.add_checker('plugin1', alert_group='Vulnerability1', details='Service could be compromised')
    domain2 = monitor.add_checker('plugin2', alert_group='Vulnerability2', details='Service exploitable')
    url = monitor.add_checker('plugin3', log_type='web', alert_group='Vulnerability3', details='Service exploitable')
    print('Generated Domains:\n  {}\n  {}\n  {}'.format(domain1, domain2, url))

    requests.get('http://' + domain1)
    requests.get('http://' + domain2)
    requests.get(url)

    r = await monitor.check()
    print('DNS Queries Captured:', r)
    r = await monitor.check(keyword='plugin3', log_type='web')
    print('HTTP Request Captured:', r)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test_dns_log())
