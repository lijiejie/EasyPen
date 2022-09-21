import os
import sys
import wx
import asyncio
from collections import OrderedDict
import logging
import platform
from logging.handlers import RotatingFileHandler


"""
global variables share between frames / panels etc.
"""

end_me = False    # force close window may case problems, do some cleaning

busy_db_list = []
nmap_found = None    # is nmap installed
nmap_script_found = None    # is-http.nse required by our scanner
nmap_pcap_found = None
masscan_found = None        # is masscan installed

medusa_found = None
ncrack_found = None
hydra_found = None
hydra_path = ''

app_ver = 'alpha 1.0.5'

global_font_size = 9
global_user_agent = None
global_proxy_server = None
global_proxy_server_enabled = None
log_file_max_size = 200
log_file_backup_count = 5
targets_display_pagesize = 500

ports_dict = None
port_choices = None
masscan_path = ''
masscan_path_origin = ''
masscan_extra_args = ''
masscan_rate = None
masscan_ping_scan_wait = None
masscan_port_scan_wait = None
interface_for_masscan_enabled = None
interface_for_masscan = None
masscan_interfaces = []

max_num_of_scan_process = None
nmap_extra_params = ''
nmap_extra_params_enabled = None
nmap_version_intensity = None

is_windows_exe = False

if os.path.basename(sys.executable).lower() == 'easypen.exe' or sys.executable.find('python') < 0:
    root_path = os.path.dirname(sys.executable)
    is_windows_exe = True
else:
    root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# for debug, to test Windows exe file
# is_windows_exe = True

target_tree_list = []

# discover
name_brute_aborted = None
host_discover_aborted = None

# scanner
port_scan_finished = None
loop = asyncio.get_event_loop()
task_queue = asyncio.queues.Queue()
weak_pass_brute_task_queue = asyncio.queues.Queue()
scan_threads_num = 200
normal_scan_task_timeout = 2
brute_scan_enabled = False
brute_process_num = 5
brute_task_timeout = 5
brute_tool_preferred = 'hydra'

dnslog_enabled = None
dnslog_domain_postfix = ''
dnslog_user = ''
dnslog_token = ''
dnslog_api_server = ''
dns_zone_transfer_domains = ''
enable_plugin_debug = False
ldap_log_server = ''

scanner_completed = None  # task runner finished
scan_aborted = None      # notify poc_runner to clear task queue and exit


user_agreement_accepted = None
user_selected_plugins = None

# keep reference of the result list control, all plugins can save vulnerabilities by post event to it
result_list_ctrl_panel = None

# keep reference of the main frame, because too many panels need to access it
# to avoid pass frame as __init__ parameter everywhere
main_frame = None

# do not update status bar too frequently, repaint too may case performance problem
last_update_status_bar = None


def get_config():
    cwd = os.path.split(os.path.abspath(__file__))[0]
    root_dir = os.path.abspath(os.path.join(cwd, '..'))
    config_dir = os.path.join(root_dir, 'config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    # if you're a developer, you can create a config file named
    # EasyPen_dev.conf
    if os.path.exists(os.path.join(config_dir, "EasyPen_dev.conf")):
        config_file_path = os.path.join(config_dir, "EasyPen_dev.conf")
    else:
        config_file_path = os.path.join(config_dir, "EasyPen.conf")
    config = wx.FileConfig(localFilename=config_file_path)
    return config


def load_config():
    global global_font_size, global_user_agent, global_proxy_server, global_proxy_server_enabled, \
        log_file_max_size, log_file_backup_count, targets_display_pagesize, \
        masscan_path_origin, masscan_path, masscan_extra_args, masscan_rate, max_num_of_scan_process, \
        masscan_ping_scan_wait, masscan_port_scan_wait, \
        interface_for_masscan_enabled, interface_for_masscan, \
        nmap_extra_params, nmap_extra_params_enabled, nmap_version_intensity, \
        scan_threads_num, normal_scan_task_timeout, \
        brute_scan_enabled, brute_process_num, brute_task_timeout, brute_tool_preferred, \
        dnslog_enabled, dnslog_domain_postfix, dnslog_user, dnslog_token, dnslog_api_server, \
        dns_zone_transfer_domains, ldap_log_server, enable_plugin_debug, \
        user_agreement_accepted
    config = get_config()
    config.SetPath('general')
    val = config.Read('FontSize')
    if val and val.strip():
        try:
            if int(val) >= 6 and int(val) <= 16:
                global_font_size = int(val)
        except Exception as e:
            pass
    val = config.Read('UserAgent')
    if val:
        global_user_agent = val
    else:
        global_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    val = config.Read('ProxyServer')
    if val:
        global_proxy_server = val
    else:
        global_proxy_server = ""

    global_proxy_server_enabled = False
    val = config.Read('EnableProxy')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        global_proxy_server_enabled = True

    config = get_config()
    config.SetPath('general')
    val = config.Read('LogFileMaxSize').strip().upper().replace('MB', '')
    if val:
        try:
            if int(val) >= 50:
                log_file_max_size = int(val)
        except Exception as e:
            pass
    val = config.Read('LogFileBackupCount')
    if val and val.strip():
        try:
            if int(val) >= 50:
                log_file_backup_count = int(val)
        except Exception as e:
            pass
    val = config.Read('TargetsDisplayPageSize')
    if val and val.strip():
        try:
            if int(val) >= 1:
                targets_display_pagesize = int(val)
        except Exception as e:
            pass


    config = get_config()
    config.SetPath('discover')
    val = config.Read('MasScanPath')
    masscan_path_origin = val
    if os.path.exists(os.path.abspath(val)):
        masscan_path = os.path.abspath(val)
    elif os.path.exists(os.path.abspath(os.path.join(root_path, val))):
        masscan_path_origin = masscan_path = os.path.abspath(os.path.join(root_path, val))
    else:
        masscan_path_origin = masscan_path = 'masscan'

    if masscan_path.lower().endswith('.exe') and platform.system() != 'Windows':
        masscan_path_origin = masscan_path = 'masscan'

    val = config.Read('MasScanExtraArgs')
    if val:
        masscan_extra_args = val.strip()
    val = config.Read('MasScanRate')
    if val:
        masscan_rate = 1000
        if val.strip():
            try:
                if int(val) >= 200:
                    masscan_rate = int(val)
            except Exception as e:
                pass
    val = config.Read('MaxScanProcess')
    max_num_of_scan_process = 5
    if val:
        try:
           max_num_of_scan_process = int(val.strip())
        except Exception as e:
            pass
    val = config.Read('MasScanPingWait')
    masscan_ping_scan_wait = 2
    if val:
        try:
            masscan_ping_scan_wait = int(val.strip())
        except Exception as e:
            pass
    val = config.Read('MasScanPortScanWait')
    masscan_port_scan_wait = 6
    if val:
        try:
            masscan_port_scan_wait = int(val.strip())
        except Exception as e:
            pass
    interface_for_masscan_enabled = False
    val = config.Read('InterfaceForMasScanEnabled')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        interface_for_masscan_enabled = True
    val = config.Read('InterfaceForMasScan')
    if val:
        interface_for_masscan = val

    val = config.Read('NmapExtraParams')
    if val:
        nmap_extra_params = val
    nmap_extra_params_enabled = False
    val = config.Read('NmapExtraParamsEnabled')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        nmap_extra_params_enabled = True
    val = config.Read('NmapVersionIntensity')
    nmap_version_intensity = 2
    if val:
        try:
            if 2 <= int(val.strip()) <= 9:
                nmap_version_intensity = int(val.strip())
        except Exception as e:
            pass

    config = get_config()
    config.SetPath('scanner')
    val = config.Read('ScanThreadNum')
    if val:
        try:
            if int(val) >= 1 and int(val) <= 2000:
                scan_threads_num = int(val)
        except Exception as e:
            pass
    val = config.Read('NormalTaskTimeout')
    if val:
        try:
            if int(val) >= 1 and int(val) <= 20:
                normal_scan_task_timeout = int(val)
        except Exception as e:
            pass
    val = config.Read('BruteScanEnabled')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        brute_scan_enabled = True
    val = config.Read('BruteProcessNum')
    if val:
        try:
            if int(val) >= 1 and int(val) <= 20:
                brute_process_num = int(val)
        except Exception as e:
            pass
    val = config.Read('BruteTaskTimeout')
    if val:
        try:
            if int(val) >= 1 and int(val) <= 20:
                brute_task_timeout = int(val)
        except Exception as e:
            pass
    val = config.Read('BruteToolPreferred')
    if val:
        brute_tool_preferred = val
    dnslog_enabled = False
    val = config.Read('DNSLogEnabled')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        dnslog_enabled = True

    val = config.Read('DNSLogDomainPostfix')
    if val:
        dnslog_domain_postfix = val
    val = config.Read('DNSLogUser')
    if val:
        dnslog_user = val
    val = config.Read('DNSLogToken')
    if val:
        dnslog_token = val
    val = config.Read('DNSLogAPIServer')
    if val:
        dnslog_api_server = val

    val = config.Read('DNSZoneTransferDomains')
    if val:
        dns_zone_transfer_domains = '\n'.join(val.strip().replace('，', ',').split(','))

    val = config.Read('LdapLogServer')
    if val:
        ldap_log_server = val

    val = config.Read('EnablePluginDebug')
    if val and val.lower() in ['y', 'yes', '1', 'true']:
        enable_plugin_debug = True

    load_port_config()

    config = get_config()
    config.SetPath('agreement')
    val = config.Read('UserAgreeMentAccepted')
    if val:
        user_agreement_accepted = val.strip()


def load_port_config():
    global ports_dict, port_choices
    ports_dict = OrderedDict()
    config = get_config()
    config.SetPath('ports')
    more, entry_name, index = config.GetFirstEntry()
    while more:
        value = config.Read(entry_name)
        ports_dict[entry_name] = value
        more, entry_name, index = config.GetNextEntry(index)

    port_choices = []
    for name in ports_dict.keys():
        port_choices.append(name.replace('_', ' '))
    for name in ['Full Ports', 'Top Ports']:
        if name in port_choices:
            port_choices.remove(name)
            port_choices.insert(0, name)


supported_inputs = """\
Supported formats

Domain / IP / Network, with or without ports

    10.1.2.5
    10.1.2.5/24
    10.1.2.5:80
    10.1.2.5/30:80
    redis://10.1.2.3:6379
    www.lijiejie.com
    www.lijiejie.com:443
    www.lijiejie.com/30:80
    www.lijiejie.com/31
    http://www.lijiejie.com
    https://www.lijiejie.com:80/path

You can also drag multiple files into the input box
Double click on the box can empty imported files
"""


def init_logging():
    # logging
    global log_file_max_size, log_file_backup_count
    log_format = logging.Formatter('[%(asctime)s] [%(funcName)s] [%(lineno)d] %(message)s')
    logger = logging.getLogger("easy_pen")
    logger.setLevel(logging.DEBUG)
    if not os.path.exists(os.path.join(root_path, 'logs')):
        os.mkdir(os.path.join(root_path, 'logs'))
    handler = RotatingFileHandler(os.path.join(root_path, 'logs/easy_pen.log'),
                                  maxBytes=log_file_max_size * 1024 * 1024, backupCount=log_file_backup_count)
    handler.setFormatter(fmt=log_format)
    logger.addHandler(handler)
    if not os.path.exists(os.path.join(root_path, 'output')):
        os.mkdir(os.path.join(root_path, 'output'))


if __name__ == '__main__':
    app = wx.App()
    init_logging()
    config = get_config()
    config.SetPath('agreement')
    val = config.Read('UserAgreeMentAccepted')
    print(val)

    config = get_config()
    config.SetPath('ports')
    names = []
    more, value, index = config.GetFirstEntry()

    while more:
        v = config.Read(value)
        print(value, v)
        more, value, index = config.GetNextEntry(index)
    print(names)
