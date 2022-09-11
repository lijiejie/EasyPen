#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib
import glob
import os
import sys
import codecs
import logging
import asyncio
from importlib import reload
if __name__ == '__main__':
    cwd = os.path.split(__file__)[0]
    sys.path.insert(0, os.path.join(cwd, ''))
    sys.path.insert(0, os.path.join(cwd, '../tools'))
    sys.path.insert(0, os.path.join(cwd, '..'))
from lib.poc.dummy import http_client, DNSMonitor, all_dns_monitors, DEBUG_PLUGIN, all_pools
import pprint
import traceback
import lib.config as conf


logger = logging.getLogger("port_crack")
lock_pool = asyncio.Lock()
lock_monitor = asyncio.Lock()


class PocScanner(object):
    def __init__(self, task_msg, is_brute_scanner=False):
        self.task_msg = task_msg
        self.is_brute_scanner = is_brute_scanner
        self.ip = task_msg['ip']
        self.service = task_msg['service']
        if not self.service:
            self.service = 'http'
        self.port = int(task_msg['port']) if task_msg['port'] else None
        if not self.port:
            if self.service == 'http':
                self.port = 80
            if self.service == 'https':
                self.port = 443
        self.base_url = '%s://%s:%s' % (self.service, self.ip, self.port)
        self.is_http = task_msg.get('is_http', 1)
        self.is_recheck_task = True if task_msg.get('policy_name', '') == 'recheck_scan' else False
        self.scripts_list = []
        self.results = []
        self.plugin_list = [] if 'plugin_list' not in task_msg else task_msg['plugin_list']

    async def is_port_open(self):
        if not self.port:
            return True
        try:
            fut = asyncio.open_connection(self.ip, int(self.port))
            reader, writer = await asyncio.wait_for(fut, timeout=5)
            writer.close()
            try:
                await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
            except Exception as e:
                pass
            return True
        except Exception as e:
            return False

    def load_scripts(self):
        try:
            cwd = os.path.dirname(__file__)

            for _script in glob.glob(os.path.join(cwd, '../scripts/*.py')):
                if self.is_recheck_task:
                    with codecs.open(_script, encoding="utf-8") as script_file:
                        if script_file.read().find(self.task_msg['alert_group']) < 0 and \
                                (self.task_msg['alert_group'].startswith('Weak Password') and
                                 _script.find('medusa_weak_pass_scan.py') < 0):
                            continue
                script_name = os.path.basename(_script).replace('.py', '')
                if script_name.startswith('_'):
                    continue
                if self.plugin_list and script_name not in self.plugin_list:
                    continue

                if self.is_brute_scanner and script_name not in ['hydra_weak_pass_scan', 'medusa_weak_pass_scan']:
                    continue

                if not self.is_brute_scanner and script_name in ['hydra_weak_pass_scan', 'medusa_weak_pass_scan']:
                    continue

                if self.is_brute_scanner and conf.brute_tool_preferred == 'hydra' and conf.hydra_found and \
                        script_name in ['medusa_weak_pass_scan']:
                    continue

                if self.is_brute_scanner and conf.brute_tool_preferred == 'medusa' and conf.medusa_found and \
                        script_name in ['hydra_weak_pass_scan']:
                    continue

                try:
                    script_module = importlib.import_module('scripts.%s' % script_name)
                    reload(script_module)
                    if not hasattr(script_module, "do_scan"):
                        logger.error('[ERROR] script has no do_scan method: %s' % script_name)
                        continue
                    self.scripts_list.append(script_module)
                except Exception as e:
                    logger.error(traceback.format_exc())
            return len(self.scripts_list)
        except Exception as e:
            logger.error('[CMSCheckPlugin][_load_scripts] Exception %s' % str(e))

    async def scan(self, timeout):
        if not await self.is_port_open():
            logger.error('Port is not open: %s:%s ' % (self.ip, self.port))
            return []

        # DNS Monitor
        dns_monitor = DNSMonitor()
        dns_monitor.set_target(self.base_url)
        key = '%s:%s' % (self.ip, self.port)
        all_dns_monitors[key] = dns_monitor
        async with lock_monitor:
            if key + ':ref' not in all_dns_monitors:
                all_dns_monitors[key + ':ref'] = 1
            else:
                all_dns_monitors[key + ':ref'] += 1

        # Pool Reference count
        key = '%s:%s' % (self.ip, self.port)
        async with lock_pool:
            if key + ':ref' not in all_pools:
                all_pools[key + ':ref'] = 1
            else:
                all_pools[key + ':ref'] += 1

        self.load_scripts()

        coro_list = []
        for _script in self.scripts_list[:]:
            try:
                # debug
                # logger.info('exec %s %s %s %s' % (_script.__name__, self.ip, self.port, self.service))
                ret = None

                scan_coro = getattr(_script, 'do_scan')(self.ip, self.port, self.service, self.is_http, self.task_msg)
                # await scan_coro
                coro_list.append(asyncio.create_task(scan_coro))
            except Exception as e:
                logger.error('do_scan error: %s' % _script.__name__)
                logger.error(traceback.format_exc())

        results = []
        try:
            results = await asyncio.wait_for(asyncio.gather(*coro_list, return_exceptions=True), timeout=timeout)
        except asyncio.TimeoutError as e:
            for t in coro_list:
                try:
                    r = t.result()
                except BaseException as e:
                    pass
                else:
                    results.append(r)
        except asyncio.exceptions.CancelledError as e:
            pass
        except (BaseException, Exception) as e:
            logger.info('gather exception: %s' % str(e))

        for r in results:
            if r and isinstance(r, dict) and 'alert_group' in r:
                r['service'] = self.service
                r['ip'] = self.ip
                r['port'] = self.port
                r['plugin_name'] = 'poc_scan'
                logger.error('Results is')
                logger.error(r)
                self.results.append(r)

        if dns_monitor.dns_to_check:
            hit_domains = await dns_monitor.check()
            if hit_domains:
                for domain in hit_domains:
                    if not dns_monitor.dns_to_check.get(domain):
                        continue
                    alert_group, details = dns_monitor.dns_to_check.get(domain)
                    vul = {
                        'service': self.service,
                        'ip': self.ip,
                        'port': self.port,
                        'plugin_name': 'poc_scan',
                        'alert_group': alert_group,
                        'affects': self.base_url,
                        'details': 'DNS Request captured: %s\n' % (domain + '.' + dns_monitor.DOMAIN_POSTFIX) +
                                   '\n\n' + details
                    }
                    self.results.append(vul)
        if dns_monitor.web_to_check:
            for domain in dns_monitor.web_to_check:
                if await dns_monitor.check(keyword=domain, log_type='web'):
                    alert_group, details = dns_monitor.web_to_check.get(domain)
                    vul = {
                        'service': self.service,
                        'ip': self.ip,
                        'port': self.port,
                        'plugin_name': 'poc_scan',
                        'alert_group': alert_group,
                        'affects': self.base_url,
                        'details': 'HTTP Request captured: http://%s\n' % (domain + '.' + dns_monitor.DOMAIN_POSTFIX) +
                                   '\n\n' + details
                    }
                    self.results.append(vul)

        if DEBUG_PLUGIN:
            logger.info('Connection pool size: %s' % len(http_client(self.ip, self.port)._transport._pool.connections))

        key = '%s:%s' % (self.ip, self.port)
        async with lock_pool:
            all_pools[key + ':ref'] -= 1
            if all_pools[key + ':ref'] <= 0:
                await http_client(self.ip, self.port).aclose()
                all_pools.pop(key)
                all_pools.pop(key + ':ref')

        async with lock_monitor:
            all_dns_monitors[key + ':ref'] -= 1
            if all_dns_monitors[key + ':ref'] <= 0:
                all_dns_monitors.pop(key)
                all_dns_monitors.pop(key + ':ref')

        return self.results


async def test_check():
    msg = {'ip': 'easypen-test.lijiejie.com', 'port': 8080, 'service': 'http', 'is_http': True, 'policy_name': '',
           'plugin_list': []}

    s = PocScanner(msg)
    r = await s.scan(timeout=120)
    pprint.pprint(r)


if __name__ == '__main__':
    logger = logging.getLogger("port_crack")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # add ch to logger
    logger.addHandler(ch)
    loop = asyncio.get_event_loop()
    task = loop.create_task(test_check())
    loop.run_until_complete(task)
