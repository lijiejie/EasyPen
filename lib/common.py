import datetime
import platform
import os
import shutil
import subprocess
import re
import wx
import glob
import codecs
import time
import logging
from netaddr import IPNetwork
import urllib.parse as urlparse
import lib.config as conf
import wx.lib.delayedresult as delayed_result


pattern_ip = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
logger = logging.getLogger("easy_pen")


def is_ip_addr(s):
    try:
        ret = pattern_ip.search(s)
        if ret:
            return all([0 <= int(x) <= 255 for x in s.split('.')])
    except Exception as e:
        pass
    return False


def is_port_num(s):
    try:
        s = int(s)
        return 1 <= s <= 65535
    except Exception as e:
        pass
    return False


def log_output(msg):
    wx.LogMessage(msg)
    logger.debug(msg)


def now_time():
    s = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
    return s


def is_intranet(ip):
    ret = ip.split('.')
    if not len(ret) == 4:
        return False
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 31:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False


def get_output_tmp_path(file_name):
    folder_name = datetime.datetime.now().strftime('%Y-%m-%d')
    folder_path = os.path.join(conf.root_path, 'output/' + folder_name)
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    return os.path.abspath(os.path.join(folder_path, file_name))


def check_required_tools():
    # nmap is required
    cmd = 'where nmap' if platform.system() == 'Windows' else 'which nmap'
    try:
        out = subprocess.check_output(cmd, shell=True).strip()
        nmap_found = True
        if platform.system() == 'Windows':
            script_dir = os.path.dirname(out).decode() + '/scripts/'
        else:
            script_dir = '/usr/share/nmap/scripts/'
    except Exception as e:
        return False, False, False, False, False, True

    # is-http.nse is required
    target_file = os.path.join(script_dir, 'is-http.nse')
    if not os.path.exists(target_file):
        try:
            cwd = os.path.split(os.path.abspath(__file__))[0]
            shutil.copyfile(os.path.join(cwd, 'is-http.nse'), target_file)    # try copy file
            script_found = os.path.exists(target_file)
        except Exception as e:
            log_output('[ERROR] Fail to copy is-http.nse %s' % str(e))
            script_found = False
    else:
        script_found = True

    # npcap may fail under windows, let's test if scan works
    try:
        # SYN Scan Test
        subprocess.check_output('nmap 127.0.0.1 -p 2022 -sS', stderr=subprocess.STDOUT, shell=True)
        nmap_pcap_found = True
    except Exception as e:
        nmap_pcap_found = False

    medusa_found = False
    ncrack_found = False

    if platform.system() == 'Windows':
        try:
            output = subprocess.check_output('ncrack -V', stderr=subprocess.STDOUT, shell=True)
            if output.find(b'http://ncrack.org') >= 0 or output.find(b'Ncrack version') >= 0:
                ncrack_found = True
        except Exception as e:
            pass
    else:
        try:
            output = subprocess.check_output('medusa -V', stderr=subprocess.STDOUT, shell=True)
            if output.find(b'jmk@foofus.net') >= 0 or output.find(b'http://www.foofus.net') >= 0:
                medusa_found = True
        except Exception as e:
            pass

    hydra_found = False
    if platform.system() == 'Windows':
        hydra_path = os.path.abspath(os.path.join(conf.root_path, 'tools/hydra/hydra.exe'))
        if os.path.exists(hydra_path):
            hydra_found = True
            conf.hydra_path = hydra_path
        else:
            log_output('Can not find hydra executable file')
    else:
        try:
            output = subprocess.check_output('hydra -h', stderr=subprocess.STDOUT, shell=True)
            if output.find(b'https://github.com/vanhauser-thc/thc-hydra') >= 0 or \
                    output.find(b'by van Hauser/THC & David Maciejak') >= 0:
                hydra_found = True
        except Exception as e:
            if hasattr(e, 'output'):
                if e.output.find(b'https://github.com/vanhauser-thc/thc-hydra') >= 0 or \
                        e.output.find(b'by van Hauser/THC & David Maciejak') >= 0:
                    hydra_found = True
        if hydra_found:
            try:
                conf.hydra_path = subprocess.check_output('which hydra',
                                                          stderr=subprocess.STDOUT, shell=True).decode().strip()
            except Exception as e:
                pass

    return nmap_found, script_found, nmap_pcap_found, medusa_found, ncrack_found, hydra_found


def get_hostname_port_mask(s):
    """
        10.1.2.5/30:80
    """
    hostname = mask = port = None
    if s.find('://') > 0:
        s = s.split('://')[1]    # remove protocol name

    if 0 <= s.find(':') < s.find('/') and s.find('/') >= 0:    # :port/path, eg. lijiejie.com:443/path
        s = s.split('/')[0]
        if len(s.split(':')) == 2:
            hostname, port = s.split(':')
    else:
        ret = s.replace(':', ' ').replace('/', ' ').split()
        if len(ret) == 3:
            hostname, mask, port = ret
        elif len(ret) == 2:
            if s.find(':') > 0:
                hostname, port = ret
            else:
                hostname, mask = ret
        else:
            hostname = ret[0]
    return hostname, port, mask


def check_environment(frame):
    delayed_result.startWorker(check_required_tools_callback, check_required_tools, cargs=(frame,))


def check_required_tools_callback(result, frame):
    conf.nmap_found, conf.nmap_script_found, conf.nmap_pcap_found, \
    conf.medusa_found, conf.ncrack_found, conf.hydra_found = \
        nmap_found, nmap_script_found, nmap_pcap_found, medusa_found, ncrack_found, hydra_found = result.get()

    if not nmap_found:
        frame.discover_panel.brute_panel.chk_port_scan.Enable(False)
        frame.discover_panel.host_discover_panel.chk_port_scan.Enable(False)
        wx.MessageDialog(frame, 'Nmap missing, please install nmap \nEnsure it can be found in $PATH', 'EasyPen',
                         wx.ICON_INFORMATION).ShowModal()
        log_output('Nmap missing, please install nmap or add it to $PATH')
    elif not nmap_script_found:
        wx.MessageDialog(frame, 'Nmap script missing\nRun this program as root or administrator\n'
                                'So it can copy script to nmap folder',
                         'EasyPen', wx.ICON_INFORMATION).ShowModal()
        log_output('Nmap script missing, run as root or administrator to copy script')
    elif not nmap_pcap_found:
        wx.MessageDialog(frame, 'Nmap NPcap Missing.\nYou can get NPcap from https://npcap.org',
                         'EasyPen', wx.ICON_INFORMATION).ShowModal()
        log_output('Nmap NPcap Missing, install NPcap from https://npcap.org')

    # check if masscan ready
    masscan_found = False
    win_pcap_npcap_missing = False
    if platform.system() == 'Windows':
        try:
            p = subprocess.Popen(conf.masscan_path + ' -v', stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            output, error = p.communicate()
            if output.find(b'masscan --nmap') >= 0:
                masscan_found = True
                error_msg = b'HINT: you must install either WinPcap or Npcap'
                if error.find(error_msg) >= 0 or output.find(error_msg) >= 0:
                    log_output('You must install either WinPcap or Npcap')
                    win_pcap_npcap_missing = True
            else:
                log_output('Masscan test failed.')
        except Exception as e:
            log_output('Masscan test failed: %s' % str(e))

    else:
        try:
            cmd = conf.masscan_path
            if conf.masscan_extra_args:
                cmd += ' ' + conf.masscan_extra_args
            p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
            output, error = p.communicate()
            if output.find(b'masscan --nmap') >= 0 or error.find(b'masscan --nmap') >= 0:
                masscan_found = True
                error_msg = b'HINT: you must install either WinPcap or Npcap'
                if error.find(error_msg) >= 0 or output.find(error_msg) >= 0:
                    log_output('You must install either WinPcap or Npcap')
                    win_pcap_npcap_missing = True
            else:
                log_output('Masscan test fail, must run as root to use masscan')
                conf.masscan_path = 'masscan'    # test OK under Linux

        except Exception as e:
            log_output('Masscan test fail: %s' % str(e))
            masscan_found = False
    frame.discover_panel.brute_panel.chk_port_scan.Enable(masscan_found & nmap_found)

    if platform.system() == 'Windows':
        # alpha version, at present we do support hydra only
        # ncrack has some performance and accuracy issues
        if not hydra_found:
            log_output('Hydra not found, weak passwords brute disabled, '
                       'install hydra: https://github.com/vanhauser-thc/thc-hydra')
    else:
        if not medusa_found and not hydra_found:
            log_output('Neither of hydra and medusa was found, weak pass brute disabled.')

    if masscan_found and not win_pcap_npcap_missing:
        try:
            output = subprocess.check_output(conf.masscan_path + ' --iflist', stderr=subprocess.STDOUT, shell=True)
            for line in output.splitlines():
                line = line.strip()
                if line:
                    ret = line.split(b'\t')
                    description = ret[1]
                    _ = ret[0].strip().split()
                    if _[1].startswith(b'\\Device\\'):
                        name = _[0]
                    else:
                        name = _[1]
                    try:
                        conf.masscan_interfaces.append('%s %s' % (name.decode(), description.decode()))
                    except Exception as e:
                        try:
                            conf.masscan_interfaces.append('%s %s' % (name.decode('gbk'), description.decode('gbk')))
                        except Exception as e:
                            pass
            if conf.masscan_interfaces:
                if conf.interface_for_masscan in conf.masscan_interfaces:
                    value = conf.interface_for_masscan
                else:
                    value = conf.masscan_interfaces[0]
            else:
                value = None
            if 'Discover Options' in conf.main_frame.settings_panel.right_panel.panel_list:
                panel = conf.main_frame.settings_panel.right_panel.panel_list['Discover Options']
                panel.cbo_masscan_interface.Clear()
                for item in conf.masscan_interfaces:
                    panel.cbo_masscan_interface.Append(item)
                panel.cbo_masscan_interface.SetValue(value)
        except Exception as e:
            log_output('Fail to list interfaces for masscan')


def set_button_img(button, img):
    img = wx.Image(img).ConvertToBitmap()
    button.SetBitmap(img)
    button.SetBitmapCurrent(img)
    button.SetBitmapPressed(img)
    button.SetBitmapFocus(img)


def get_all_scripts(keyword=''):
    keyword = keyword.lower()
    all_scripts = {}
    index = 1
    pattern_group = re.compile(r"'alert_group':\s*'(.+)'")
    pattern_author = re.compile("author = '(.*)'")
    path = os.path.join(conf.root_path, 'scripts/*.py')
    for script_file in glob.glob(path):
        if not path.endswith('.py'):
            continue
        script_name = os.path.basename(script_file)[:-3]
        if script_name.startswith('__'):
            continue
        with codecs.open(script_file, encoding='utf-8') as f:
            code = f.read()
            m = pattern_group.search(code)
            alert_group = m.group(1) if m else ''
            m = pattern_author.search(code)
            author = m.group(1) if m else ''
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(script_file)).strftime("%Y-%m-%d %H:%M:%S")
        if keyword and script_name.lower().find(keyword) < 0 and alert_group.find(keyword) < 0:
            continue
        all_scripts[index] = (script_name, alert_group, author, mtime)
        index += 1
    return all_scripts


def get_git_hack_folder(url):
    try:
        return urlparse.urlparse(url).netloc.replace(':', '_')
    except:
        return 'not_existed_folder'


def get_abs_path(path):
    try:
        return os.path.abspath(os.path.join(conf.root_path, path))
    except Exception as e:
        log_output('Invalid path: %s' % path)
        return ''


def edit_ports(profile_name):
    if conf.main_frame:
        tree = conf.main_frame.settings_panel.option_tree_panel.option_tree
        item = tree.FindItem(tree.root_node, 'Port Scan Profiles')
        tree.DoSelectItem(item)
        panel = conf.main_frame.settings_panel.right_panel.panel_list['Port Scan Profiles']
        panel.cbo_port_list.SetValue(profile_name)
        panel.change_ports(None)
        conf.main_frame.notebook.SetSelection(4)   # config tab


def refresh_cbo_port_list():
    if conf.main_frame:
        for panel in [conf.main_frame.discover_panel.brute_panel, conf.main_frame.discover_panel.host_discover_panel,
                      conf.main_frame.scan_panel.scan_box]:
            old_value = panel.cbo_port_list.GetValue()
            panel.cbo_port_list.Clear()
            for item in conf.port_choices:
                panel.cbo_port_list.Append(item)
            if old_value in conf.port_choices:
                panel.cbo_port_list.SetValue(old_value)
            else:
                panel.cbo_port_list.SetValue(conf.port_choices[0])


def show_progress_bar(interval=200):
    if conf.main_frame:
        conf.main_frame.progress_bar_timer.Start(interval)
        conf.main_frame.progress_bar.Show()


def hide_progress_bar():
    if conf.main_frame:
        conf.main_frame.progress_bar_timer.Stop()
        conf.main_frame.progress_bar.Hide()


def count_num_of_ips(items):
    count = 0
    for item in items:
        item = str(item).strip()
        if item.find('/') < 0:
            count += 1
        else:
            count += IPNetwork(item).size
    return count


if __name__ == '__main__':
    print(get_output_tmp_path('test'))
    print("is_port_num('80') ->", is_port_num('80'))
    print("is_ip_addr('10.1.2.4') -> ", is_ip_addr('10.1.2.4'))
    print("is_ip_addr('10.1.2.256') -> ", is_ip_addr('10.1.2.256'))
    print("is_ip_addr('10.1.2.3a') -> ", is_ip_addr('10.1.2.3a'))
    print(check_required_tools())

    tests = """\
10.1.2.5
10.1.2.5/24
10.1.2.5:80
10.1.2.5/30:80
www.lijiejie.com
www.lijiejie.com:443
www.lijiejie.com/30:80
www.lijiejie.com:80/30
redis://10.1.2.3:6379
www.lijiejie.com/31
http://www.baidu.com
https://www.baidu.com:80/path
"""
    for item in tests.strip().split('\n'):
        print(item, '->', get_hostname_port_mask(item))

    print(get_all_scripts())
