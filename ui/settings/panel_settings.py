import wx
import wx.lib.newevent
import importlib
import os
import lib.config as conf
from lib.common import refresh_cbo_port_list
import wx.lib.scrolledpanel as scrolled
from ui.settings.panel_option_tree import OptionTreePanel
from ui.settings.settings_ui.panel_general_settings import GeneralSettingsPanel


class RightPanel(scrolled.ScrolledPanel):
    def __init__(self, parent):
        scrolled.ScrolledPanel.__init__(self, parent, -1, style=wx.CLIP_CHILDREN, size=(100, 100))
        self.current_panel_name = 'General'
        self.current_panel = general_panel = GeneralSettingsPanel(self)
        self.panel_list = {'General': general_panel}

        self.sizer = sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.current_panel, 1, wx.ALL | wx.EXPAND, 5)
        self.SetSizer(sizer)
        self.SetupScrolling()


class SettingsPanel(wx.Panel):
    def __init__(self, frame):
        if hasattr(frame, 'notebook'):
            wx.Panel.__init__(self, frame.notebook, -1, style=wx.CLIP_CHILDREN)
        else:
            wx.Panel.__init__(self, frame, -1, style=wx.CLIP_CHILDREN)
        self.frame = frame
        self.option_tree_panel = OptionTreePanel(self)
        self.right_panel = RightPanel(self)

        apply_button = wx.Button(self, -1, "Apply Changes", size=(-1, 30))
        apply_button.Bind(wx.EVT_BUTTON, self.do_apply_changes)

        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        button_sizer.AddStretchSpacer(1)
        button_sizer.Add(apply_button, 0, wx.ALL, 15)

        right_sizer = wx.BoxSizer(wx.VERTICAL)
        right_sizer.Add(self.right_panel, 1, wx.EXPAND)
        right_sizer.Add(button_sizer, 0)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self.option_tree_panel, 0, wx.ALL | wx.EXPAND, 5)
        sizer.Add(right_sizer, 1, wx.ALL | wx.EXPAND, 2)
        self.SetSizer(sizer)

    @staticmethod
    def write_config(path, name, value):
        config = conf.get_config()
        config.SetPath(path)
        config.Write(name, value)
        config.Flush()

    def do_apply_changes(self, event):
        current_panel_name = self.right_panel.current_panel_name
        current_panel = self.right_panel.current_panel
        changed = False

        if current_panel_name == 'Port Scan Profiles':
            name = current_panel.cbo_port_list.GetValue().replace(' ', '_')
            ports = current_panel.txt_ports.GetValue().strip().replace('，', ',')
            if not ports:
                wx.MessageBox('Ports can not be empty', 'Port Scan Profiles', wx.ICON_WARNING)
            else:
                self.write_config('ports', name, ports)
                conf.load_port_config()
                wx.MessageBox('Port profile saved', 'Port Scan Profiles', wx.ICON_INFORMATION)
                refresh_cbo_port_list()

        elif current_panel_name == 'General':

            user_agent = current_panel.txt_user_agent.GetValue().strip()
            if user_agent != conf.global_user_agent:
                changed = True
                conf.global_user_agent = user_agent
                self.write_config('general', 'UserAgent', user_agent)

            enable_proxy = current_panel.chk_enable_proxy.GetValue()
            if enable_proxy != conf.global_proxy_server_enabled:
                changed = True
                conf.global_proxy_server_enabled = enable_proxy
                self.write_config('general', 'EnableProxy', str(enable_proxy).lower())
                # reload dummy to take effect immediately
                script_module = importlib.import_module('lib.poc.dummy')
                importlib.reload(script_module)

            http_proxy = current_panel.txt_http_proxy.GetValue().strip()
            if http_proxy != conf.global_proxy_server:
                changed = True
                conf.global_proxy_server = http_proxy
                self.write_config('general', 'ProxyServer', http_proxy)

            log_file_size = current_panel.txt_log_file_size.GetValue().strip()
            if log_file_size != str(conf.log_file_max_size):
                changed = True
                conf.log_file_max_size = int(log_file_size)
                self.write_config('general', 'LogFileMaxSize', '%sMB' % log_file_size)

            num_of_log_files = current_panel.cbo_num_of_log_files.GetValue().strip()
            if num_of_log_files != str(conf.log_file_backup_count):
                changed = True
                conf.log_file_backup_count = int(num_of_log_files)
                self.write_config('general', 'LogFileBackupCount', num_of_log_files)

            ui_font_size = current_panel.cbo_ui_font_size.GetValue().strip()
            if ui_font_size != str(conf.global_font_size):
                changed = True
                conf.global_font_size = int(ui_font_size)
                self.write_config('general', 'FontSize', ui_font_size)

            targets_display_pagesize = current_panel.txt_targets_page_size.GetValue().strip()
            if targets_display_pagesize != str(conf.targets_display_pagesize):
                changed = True
                conf.targets_display_pagesize = int(targets_display_pagesize)
                self.write_config('general', 'TargetsDisplayPageSize', targets_display_pagesize)

            if changed:
                wx.MessageBox('Changes saved \nSome changes may require restart to take effect',
                              'General Settings', wx.ICON_INFORMATION)

        elif current_panel_name == 'Discover Options':
            num_of_nmap_masscan = current_panel.cbo_scan_process.GetValue().strip()
            if num_of_nmap_masscan != str(conf.max_num_of_scan_process):
                changed = True
                conf.max_num_of_scan_process = int(num_of_nmap_masscan)
                self.write_config('discover', 'MaxScanProcess', num_of_nmap_masscan)

            val = current_panel.txt_masscan_path.GetValue().strip()
            if val != conf.masscan_path_origin:
                changed = True
                if os.path.exists(os.path.abspath(val)):
                    conf.masscan_path = os.path.abspath(val)
                elif os.path.exists(os.path.abspath(os.path.join(conf.root_path, val))):
                    conf.masscan_path = os.path.abspath(os.path.join(conf.root_path, val))
                else:
                    wx.MessageBox('Specified masscan file not found', 'Masscan Settings', wx.ICON_ERROR)
                    return
                conf.masscan_path_origin = val
                self.write_config('discover', 'MasScanPath', val)

            masscan_rate = current_panel.txt_masscan_rate.GetValue().strip()
            if masscan_rate != str(conf.masscan_rate):
                changed = True
                conf.masscan_rate = masscan_rate
                self.write_config('discover', 'MasScanRate', masscan_rate)

            masscan_ping_wait = current_panel.cbo_ping_wait.GetValue().strip()
            if masscan_ping_wait != str(conf.masscan_ping_scan_wait):
                changed = True
                conf.masscan_ping_scan_wait = int(masscan_ping_wait)
                self.write_config('discover', 'MasScanPingWait', masscan_ping_wait)

            masscan_port_scan_wait = current_panel.cbo_port_scan_wait.GetValue().strip()
            if masscan_port_scan_wait != str(conf.masscan_port_scan_wait):
                changed = True
                conf.masscan_port_scan_wait = int(masscan_port_scan_wait)
                self.write_config('discover', 'MasScanPortScanWait', masscan_port_scan_wait)

            interface_for_masscan_enabled = current_panel.chk_masscan_interface.GetValue()
            if interface_for_masscan_enabled != conf.interface_for_masscan_enabled:
                changed = True
                conf.interface_for_masscan_enabled = interface_for_masscan_enabled
                self.write_config('discover', 'InterfaceForMasScanEnabled', str(interface_for_masscan_enabled).lower())
                if interface_for_masscan_enabled and current_panel.cbo_masscan_interface.GetValue() != 'loading':
                    self.write_config('discover', 'InterfaceForMasScan',
                                      current_panel.cbo_masscan_interface.GetValue())

            nmap_extra_params_enabled = current_panel.chk_nmap_extra_params.GetValue()
            if nmap_extra_params_enabled != conf.nmap_extra_params_enabled:
                changed = True
                conf.nmap_extra_params_enabled = nmap_extra_params_enabled
                self.write_config('discover', 'NmapExtraParamsEnabled', str(nmap_extra_params_enabled).lower())

            nmap_extra_params = current_panel.txt_nmap_extra_params.GetValue().strip()
            if nmap_extra_params != conf.nmap_extra_params:
                changed = True
                conf.nmap_extra_params = nmap_extra_params
                self.write_config('discover', 'NmapExtraParams', nmap_extra_params)

            nmap_version_intensity = current_panel.cbo_nmap_version_intensity.GetValue().strip()
            if nmap_version_intensity != str(conf.nmap_version_intensity):
                changed = True
                conf.nmap_version_intensity = int(nmap_version_intensity)
                self.write_config('discover', 'NmapVersionIntensity', nmap_version_intensity)

            if changed:
                wx.MessageBox('Changes saved \nSome changes may require restart to take effect',
                              'General Settings', wx.ICON_INFORMATION)

        elif current_panel_name == 'Scanner Options':
            scan_threads = current_panel.txt_scan_threads.GetValue().strip()
            if scan_threads != str(conf.scan_threads_num):
                changed = True
                conf.scan_threads_num = int(scan_threads)
                self.write_config('scanner', 'ScanThreadNum', scan_threads)

            normal_scan_task_timeout = current_panel.txt_task_timeout.GetValue().strip()
            if normal_scan_task_timeout != str(conf.normal_scan_task_timeout):
                changed = True
                conf.normal_scan_task_timeout = int(normal_scan_task_timeout)
                self.write_config('scanner', 'NormalTaskTimeout', normal_scan_task_timeout)

            enable_weak_pass_brute = current_panel.chk_enable_weak_pass_brute.GetValue()
            if enable_weak_pass_brute != conf.brute_scan_enabled:
                changed = True
                conf.brute_scan_enabled = enable_weak_pass_brute
                self.write_config('scanner', 'BruteScanEnabled', str(enable_weak_pass_brute).lower())

            brute_process_num = current_panel.cbo_scan_process.GetValue().strip()
            if brute_process_num != str(conf.brute_process_num):
                changed = True
                conf.brute_process_num = int(brute_process_num)
                self.write_config('scanner', 'BruteProcessNum', brute_process_num)

            brute_task_timeout = current_panel.txt_brute_task_timeout.GetValue().strip()
            if brute_task_timeout != str(conf.brute_task_timeout):
                changed = True
                conf.brute_task_timeout = int(brute_task_timeout)
                self.write_config('scanner', 'BruteTaskTimeout', brute_task_timeout)

            brute_tool_preferred = current_panel.cbo_preferred_tool.GetValue().strip()
            if brute_tool_preferred != str(conf.brute_tool_preferred):
                changed = True
                conf.brute_tool_preferred = brute_tool_preferred
                self.write_config('scanner', 'BruteToolPreferred', brute_tool_preferred)

            dnslog_enabled = current_panel.chk_enable_dnslog.GetValue()
            if dnslog_enabled != conf.dnslog_enabled:
                changed = True
                conf.dnslog_enabled = dnslog_enabled
                self.write_config('scanner', 'DNSLogEnabled', str(dnslog_enabled).lower())

            dnslog_postfix = current_panel.txt_dnslog_postfix.GetValue().strip()
            if dnslog_postfix != str(conf.dnslog_domain_postfix):
                changed = True
                conf.dnslog_domain_postfix = dnslog_postfix
                self.write_config('scanner', 'DNSLogDomainPostfix', dnslog_postfix)

            dnslog_user = current_panel.txt_dnslog_user.GetValue().strip()
            if dnslog_user != str(conf.dnslog_user):
                changed = True
                conf.dnslog_user = dnslog_user
                self.write_config('scanner', 'DNSLogUser', dnslog_user)

            dnslog_token = current_panel.txt_dnslog_token.GetValue().strip()
            if dnslog_token != str(conf.dnslog_token):
                changed = True
                conf.dnslog_token = dnslog_token
                self.write_config('scanner', 'DNSLogToken', dnslog_token)

            dnslog_api_server = current_panel.txt_dnslog_api_server.GetValue().strip()
            if dnslog_api_server != str(conf.dnslog_api_server):
                changed = True
                conf.dnslog_api_server = dnslog_api_server
                self.write_config('scanner', 'DNSLogAPIServer', dnslog_api_server)

            dns_zones = current_panel.txt_dns_zones.GetValue().strip()
            if dns_zones != conf.dns_zone_transfer_domains:
                changed = True
                conf.dns_zone_transfer_domains = dns_zones
                str_value = ','.join(dns_zones.strip().replace('\r', '').split('\n')).replace(',,', ',')
                self.write_config('scanner', 'DNSZoneTransferDomains', str_value)

            ldap_log_server = current_panel.txt_ldap_server.GetValue().strip()
            if ldap_log_server != conf.ldap_log_server:
                changed = True
                conf.ldap_log_server = ldap_log_server
                self.write_config('scanner', 'LdapLogServer', ldap_log_server)

            enable_plugin_debug = current_panel.chk_enable_plugin_debug.GetValue()
            if enable_plugin_debug != conf.enable_plugin_debug:
                changed = True
                conf.enable_plugin_debug = enable_plugin_debug
                self.write_config('scanner', 'EnablePluginDebug', str(enable_plugin_debug).lower())

            if changed:
                wx.MessageBox('Changes saved',
                              'Scanner Settings', wx.ICON_INFORMATION)
        event.Skip()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    win = SettingsPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
