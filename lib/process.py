# -*- encoding:utf-8 -*-
# subprocess with timeout

import subprocess
import time
import wx
import os
import json
import logging
import random
import psutil
import signal
import lib.config as conf
from lib.common import get_output_tmp_path, log_output
from lib.nmap_parser import parse_nmap_output

cwd = os.path.split(os.path.abspath(__file__))[0]
root_dir = os.path.abspath(os.path.join(cwd, '..'))
logger = logging.getLogger("easy_pen")


def run_cmd_with_timeout(cmd, timeout, shell=True):
    try:
        start_time = time.time()
        p = subprocess.Popen(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, shell=shell)
        logger.debug('Cmd: %s' % cmd)
        logger.debug('PID: %s' % p.pid)
        while p.poll() is None:
            if time.time() - start_time > timeout:
                msg = '[run_cmd_with_timeout.exception] Nmap process timed out: %s' % cmd
                wx.LogMessage(msg)
                p.terminate()
            else:
                time.sleep(0.2)
        output, error = p.communicate()
        logger.debug('Process terminated, PID: %s, return code is %s' % (p.pid, p.returncode))
        if error and \
                error.find(b'Your --min-parallelism option is pretty high!') < 0 and \
                error.find(b'Starting masscan') < 0:
            err_msg = '[run_cmd_with_timeout.exception]: %s' % error
            logger.error(err_msg)
            wx.LogMessage(err_msg)
            wx.LogMessage('[cmd] %s' % cmd)
        return
    except Exception as e:
        import traceback
        traceback.print_exc()
        err_msg = '[run_cmd_with_timeout.exception]: %s' % str(e)
        log_output(err_msg)


def do_masscan(ip_set, scan_ports, return_by_ports=True, exe_path=None, ping_only=False):
    ip_file_path = get_output_tmp_path('masscan_ips_%s_%s.txt' % (time.time(), round(random.random(), 3)))
    with open(ip_file_path, 'w') as f:
        for ip in ip_set:
            f.write(ip + '\n')

    output_file_path = get_output_tmp_path('masscan_output_%s_%s.json' % (time.time(), round(random.random(), 3)))
    if exe_path is None:
        exe_path = conf.masscan_path
    if exe_path.startswith('./'):
        exe_path = os.path.join(root_dir, exe_path.lstrip('./'))
    if ping_only:
        cmd = "%s --ping --wait %s -iL %s -oJ %s" % (
            exe_path, conf.masscan_ping_scan_wait, ip_file_path, output_file_path)
    else:
        cmd = "%s -p%s -iL %s --rate=%s --wait %s -oJ %s" % (
            exe_path, scan_ports, ip_file_path, conf.masscan_rate, conf.masscan_port_scan_wait, output_file_path)

    if conf.interface_for_masscan_enabled and conf.interface_for_masscan and conf.interface_for_masscan != 'loading':
        cmd += ' -e ' + conf.interface_for_masscan.split()[0]

    run_cmd_with_timeout(cmd, 1800, shell=True)

    if not os.path.exists(output_file_path):
        return {}

    if os.path.getsize(output_file_path) == 0:
        try:
            os.remove(ip_file_path)
            os.remove(output_file_path)
        except Exception as e:
            pass
        return {}

    masscan_result = {}   # can be grouped by ip or by port
    with open(output_file_path, "r") as f:
        content = f.read()
        try:
            data = json.loads(content)
        except Exception as e:
            data = fix_incorrect_json(content)
        for line in data:
            if 'ports' not in line:
                continue
            if return_by_ports:
                for port in line['ports']:
                    if port['port'] not in masscan_result:
                        masscan_result[port['port']] = set([])
                    masscan_result[port['port']].add(line['ip'])
            else:
                # return by IP
                if line['ip'] not in masscan_result:
                    masscan_result[line['ip']] = set([])
                for port in line['ports']:
                    masscan_result[line['ip']].add(port['port'])
    try:
        os.remove(ip_file_path)
        os.remove(output_file_path)
    except Exception as e:
        pass
    return masscan_result


def fix_incorrect_json(s):
    # try to fix masscan incorrect json output
    try:
        s = s.strip()
        for name in ['ip', 'ports', 'port', 'proto', 'status', 'reason', 'ttl', 'finished']:
            s = s.replace('%s:' % name, '"%s":' % name)
        s = '[%s]' % s
        return json.loads(s)
    except Exception as e:
        return []


def do_nmap_scan(port, ips):
    ip_file_path = os.path.join(root_dir, 'tools/nmap/nmap_ips_%s_%s.txt' % (
        str(time.time()), round(random.random(), 3)))
    with open(ip_file_path, 'w') as f:
        for ip in ips:
            f.write(ip + '\n')

    if conf.nmap_extra_params_enabled and conf.nmap_extra_params:
        extra_params = conf.nmap_extra_params
    else:
        extra_params = ''
    cmd_template = 'nmap -n -p%s %s -sS -sV --version-intensity ' + str(conf.nmap_version_intensity) + \
                   ' --script=is-http ' \
                   '--script-args "' + conf.global_user_agent + '" -oX %s -iL %s'
    out_file_path = 'tools/nmap/port_scan_output_%s_%s.xml' % (str(int(time.time())), round(random.random(), 3))
    cmd = cmd_template % (port, extra_params, out_file_path, ip_file_path)
    run_cmd_with_timeout(cmd, 600, shell=True)
    if os.path.exists(out_file_path):
        hosts = parse_nmap_output(out_file_path)
        try:
            os.remove(ip_file_path)
            os.remove(out_file_path)
        except Exception as e:
            pass
        return hosts
    else:
        return []


def kill_child_processes(parent_pid, sig=signal.SIGTERM):
    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess as e:
        return
    children = parent.children(recursive=True)
    for process in children:
        process.send_signal(sig)


if __name__ == '__main__':
    # run_cmd_with_timeout('ping -n 1000 www.lijiejie.com', 10)
    r = do_masscan({'192.168.1.1/24'}, "213", exe_path='../tools/masscan.exe', return_by_ports=True)
    print(r)
