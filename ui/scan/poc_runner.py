#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
    This module creates a poc execute thread that process targets queue feed by port scan
"""

import wx
import os
import sys
import threading
import time
import json
import traceback
import psutil
import asyncio
import logging
import socket
import lib.config as conf
from logging.handlers import RotatingFileHandler
from logging import Formatter
from lib.poc_scan import PocScanner
from lib.event import VulEvent, LogEvent, StatusEvent

LOG_PATH = os.path.join(conf.root_path, 'logs')
if not os.path.isdir(LOG_PATH):
    os.makedirs(LOG_PATH)

handler = RotatingFileHandler(os.path.join(LOG_PATH, 'poc_runner.log'), maxBytes=200 * 1024 * 1024, backupCount=5)
handler.setFormatter(Formatter('[%(asctime)-15s] [%(funcName)s] [%(lineno)d] %(message)s'))
logger = logging.getLogger("port_crack")
logger.setLevel(logging.INFO)
logger.addHandler(handler)


loop = conf.loop
task_queue = conf.task_queue
weak_pass_brute_task_queue = conf.weak_pass_brute_task_queue


if sys.platform == 'win32':
    def _call_connection_lost(self, exc):
        try:
            self._protocol.connection_lost(exc)
        finally:
            if hasattr(self._sock, 'shutdown'):
                try:
                    if self._sock.fileno() != -1:
                        self._sock.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    pass
                    # logger.error('_call_connection_lost exception: %s' % str(e))
            self._sock.close()
            self._sock = None
            server = self._server
            if server is not None:
                server._detach()
                self._server = None

    asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _call_connection_lost


class Scanner(object):
    def __init__(self, task_msg, exclude_ips, is_brute_scanner=False):
        self.task_msg = task_msg
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
        self.is_scan_from_user = True if 'task_id' in task_msg else False
        self.white_list = exclude_ips
        self.is_brute_scanner = is_brute_scanner
        self.start_time = time.time()

    async def scan(self):
        try:
            if self.ip in self.white_list:
                logger.info('[White List IP] %s://%s:%s' % (self.service, self.ip, self.port))
                return True

            # 办公网忽略9100打印端口
            try:
                if self.ip.startswith('10.') and len(self.ip.split(".")) == 4 and \
                        0 <= int(self.ip.split(".")[1]) <= 9 and self.port == 9100:
                    logger.info("[printer ip] %s://%s:%s" % (self.service, self.ip, self.port))
                    return True
            except Exception as e:
                logger.info("[printer ip] error: {}".format(repr(e)))

            t = '%s://%s:%s' % (self.service, self.ip, self.port)
            t = t.lstrip('://').rstrip(':')
            logger.info('Scan: %s' % t)
            start_time = time.time()
            s = PocScanner(self.task_msg, self.is_brute_scanner)
            if self.is_brute_scanner:
                timeout = int(conf.brute_task_timeout * 60)
            else:
                timeout = int(conf.normal_scan_task_timeout * 60)
            try:
                ret = await asyncio.wait_for(s.scan(timeout=timeout), timeout=timeout+60)
            except (Exception, BaseException) as e:
                ret = None
            update_status = False
            if not conf.last_update_status_bar or time.time() - conf.last_update_status_bar > 1.0:
                conf.last_update_status_bar = time.time()
                update_status = True

            if update_status:
                wx.PostEvent(conf.main_frame, StatusEvent(
                    text='Scan %s finished in %.2fs' % (t, time.time() - start_time)))
            if ret:
                wx.PostEvent(conf.result_list_ctrl_panel, VulEvent(vul=ret))
                logger.info(ret)
            return True
        except Exception as e:
            logger.error('scan Exception: \n%s' % traceback.format_exc())


async def scan_thread(task_queue):
    while True:
        if conf.scan_aborted:
            break
        if conf.port_scan_finished and task_queue.qsize() == 0:
            break
        count = 0
        while psutil.virtual_memory().available / 1024 / 1024 < 100 and \
                psutil.swap_memory().free / 1024 / 1024 < 100 and not conf.scan_aborted:
            count += 1
            logger.info('No enough memory available, counter is %s' % count)
            await asyncio.sleep(2.0)
        try:
            task_str = task_queue.get_nowait()
            task_msg = json.loads(task_str)
            s = Scanner(task_msg, [])
            await s.scan()
        except asyncio.queues.QueueEmpty as e:
            await asyncio.sleep(0.05)
        except Exception as e:
            logger.error("Scan Thread Error: \n%s" % traceback.format_exc())


async def brute_scan_thread(weak_pass_brute_task_queue):
    while True:
        if conf.scan_aborted:
            break
        if conf.port_scan_finished and weak_pass_brute_task_queue.qsize() == 0:
            break
        count = 0
        while psutil.virtual_memory().available / 1024 / 1024 < 100 and \
                psutil.swap_memory().free / 1024 / 1024 < 100 and not conf.scan_aborted:
            count += 1
            logger.info('No enough memory available, counter is %s' % count)
            await asyncio.sleep(2.0)
        try:
            task_str = weak_pass_brute_task_queue.get_nowait()
            task_msg = json.loads(task_str)
            s = Scanner(task_msg, [], is_brute_scanner=True)
            await s.scan()
        except asyncio.queues.QueueEmpty as e:
            await asyncio.sleep(0.05)
        except Exception as e:
            logger.error("Brute Scan Thread Error: \n%s" % traceback.format_exc())


def scan_main():
    tasks = []
    for _ in range(conf.scan_threads_num):
        t = loop.create_task(scan_thread(task_queue))
        tasks.append(t)

    if conf.brute_scan_enabled:
        for _ in range(conf.brute_process_num):
            t = loop.create_task(brute_scan_thread(weak_pass_brute_task_queue))
            tasks.append(t)

    loop.run_until_complete(asyncio.gather(*tasks))
    conf.scanner_completed = True
    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='Poc runner terminated.'))
    while task_queue.qsize() > 0:
        try:
            task_queue.get_nowait()
        except Exception as e:
            pass
    while weak_pass_brute_task_queue.qsize() > 0:
        try:
            weak_pass_brute_task_queue.get_nowait()
        except Exception as e:
            pass


def test_main():
    threading.Thread(target=scan_main).start()
    # 内存小于1GB时，等待可用内存
    count = 0
    while psutil.virtual_memory().available / 1024 / 1024 < 500 and \
            psutil.swap_memory().free / 1024 / 1024 < 500:
        logger.info('Available memory less than 1GB')
        count += 1
        logger.info('No available memory, counter is %s' % count)
        time.sleep(5.0)

    msg = {'ip': 'easypen-test.lijiejie.com', 'port': 8080, 'service': 'http', 'is_http': True, 'policy_name': '',
           'plugin_list': []}
    loop.call_soon_threadsafe(task_queue.put_nowait, json.dumps(msg))
    conf.port_scan_finished = True


if __name__ == '__main__':
    test_main()
