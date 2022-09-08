import wx
import lib.config as conf


class DiscoverOptionsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        label_title = wx.StaticText(self, -1, 'Discover Options')
        font = label_title.GetFont()
        font.MakeBold()
        label_title.SetFont(font)
        label_title.SetBackgroundColour((230, 230, 250))
        label_num_of_nmap_masscan = wx.StaticText(self, -1, 'Masscan && Nmap multiple processing',
                                                  size=(250, -1))
        self.cbo_scan_process = wx.ComboBox(self, -1, str(conf.max_num_of_scan_process),
                                            choices=[str(x) for x in range(1, 16)],
                                            style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_num_of_scan_process = wx.BoxSizer(wx.HORIZONTAL)
        sizer_num_of_scan_process.Add(label_num_of_nmap_masscan, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_num_of_scan_process.Add(self.cbo_scan_process, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_masscan_path = wx.StaticText(self, -1, 'Path of masscan',
                                           size=(100, -1))
        self.txt_masscan_path = wx.TextCtrl(self, -1, size=(250, -1))
        self.txt_masscan_path.SetValue(conf.masscan_path_origin)
        sizer_masscan_path = wx.BoxSizer(wx.HORIZONTAL)
        sizer_masscan_path.Add(label_masscan_path, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_masscan_path.Add(self.txt_masscan_path, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_masscan_rate = wx.StaticText(self, -1, 'Masscan rate: packets/second',
                                           size=(200, -1))
        self.txt_masscan_rate = wx.TextCtrl(self, -1, size=(150, -1))
        self.txt_masscan_rate.SetValue(str(conf.masscan_rate))
        sizer_masscan_rate = wx.BoxSizer(wx.HORIZONTAL)
        sizer_masscan_rate.Add(label_masscan_rate, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_masscan_rate.Add(self.txt_masscan_rate, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_ping_wait = wx.StaticText(self, -1, 'Seconds masscan wait before ping scan exit', size=(280, -1))
        self.cbo_ping_wait = wx.ComboBox(self, -1, str(conf.masscan_ping_scan_wait),
                                         choices=[str(x) for x in range(11)],
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(70, -1))
        sizer_ping_wait = wx.BoxSizer(wx.HORIZONTAL)
        sizer_ping_wait.Add(label_ping_wait, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_ping_wait.Add(self.cbo_ping_wait, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_port_scan_wait = wx.StaticText(self, -1, 'Seconds masscan wait before port scan exit', size=(280, -1))
        self.cbo_port_scan_wait = wx.ComboBox(self, -1, str(conf.masscan_port_scan_wait),
                                              choices=[str(x) for x in range(11)],
                                              style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(70, -1))
        sizer_port_scan_wait = wx.BoxSizer(wx.HORIZONTAL)
        sizer_port_scan_wait.Add(label_port_scan_wait, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_port_scan_wait.Add(self.cbo_port_scan_wait, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        self.chk_masscan_interface = wx.CheckBox(self, -1, 'Choose interface for masscan to solve VPN adapter issue')
        self.chk_masscan_interface.SetValue(conf.interface_for_masscan_enabled)
        if conf.masscan_interfaces:
            choices = conf.masscan_interfaces
            value = conf.interface_for_masscan if conf.interface_for_masscan in conf.masscan_interfaces \
                else conf.masscan_interfaces[0]
        else:
            choices = ['loading']
            value = 'loading'
        self.cbo_masscan_interface = wx.ComboBox(self, -1, value,
                                                 choices=choices,
                                                 style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(400, -1))

        self.chk_nmap_extra_params = wx.CheckBox(self, -1, 'Speed up nmap scan with extra params')
        self.chk_nmap_extra_params.SetValue(conf.nmap_extra_params_enabled)
        self.txt_nmap_extra_params = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(400, 60))
        self.txt_nmap_extra_params.SetValue(conf.nmap_extra_params)

        label_nmap_version_intensity = wx.StaticText(self, -1, 'Nmap version intensity (2 ~ 9)',
                                                     size=(250, -1))
        self.cbo_nmap_version_intensity = wx.ComboBox(self, -1, str(conf.nmap_version_intensity),
                                                      choices=[str(x) for x in range(2, 10)],
                                                      style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_nmap_version_intensity = wx.BoxSizer(wx.HORIZONTAL)
        sizer_nmap_version_intensity.Add(label_nmap_version_intensity, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_nmap_version_intensity.Add(self.cbo_nmap_version_intensity, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(label_title, 0, wx.LEFT | wx.TOP | wx.EXPAND, 10)
        sizer_main.Add(sizer_num_of_scan_process, 0)
        sizer_main.Add(sizer_masscan_path, 0)
        sizer_main.Add(sizer_masscan_rate, 0)
        sizer_main.Add(sizer_ping_wait, 0)
        sizer_main.Add(sizer_port_scan_wait, 0)
        sizer_main.Add((-1, 20))
        sizer_main.Add(self.chk_masscan_interface, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 5))
        sizer_main.Add(self.cbo_masscan_interface, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 20))
        sizer_main.Add(self.chk_nmap_extra_params, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 5))
        sizer_main.Add(self.txt_nmap_extra_params, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 10))
        sizer_main.Add(sizer_nmap_version_intensity, 0)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add((-1, 30))
        sizer.Add(sizer_main, 1, wx.EXPAND)
        sizer.Add((-1, 30))
        self.SetSizer(sizer)
        self.Layout()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 800))
    panel = wx.Panel(frame, -1)
    panel_git_hack = DiscoverOptionsPanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
