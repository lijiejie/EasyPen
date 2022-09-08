import wx
from lib.common import get_abs_path, refresh_cbo_port_list
import lib.config as conf


class PortsProfilePanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        label_title = wx.StaticText(self, -1, 'Port Scan Profiles')
        font = label_title.GetFont()
        font.MakeBold()
        label_title.SetFont(font)
        label_title.SetBackgroundColour((230, 230, 250))
        label_tips = wx.StaticText(self, -1, 'Use comma to concat ports, support range syntax')
        label_example = wx.StaticText(self, -1, 'Example: 1, 2, 3-10, 11, 12-20')
        label_example.SetForegroundColour((72, 118, 255))
        label = wx.StaticText(self, -1, 'Port Scan Profile')
        self.cbo_port_list = wx.ComboBox(self, -1, conf.port_choices[0],
                                         choices=conf.port_choices,
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(140, -1))
        self.cbo_port_list.Bind(wx.EVT_COMBOBOX, self.change_ports)

        add_button = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        add_button.SetToolTip("Create New Profile")
        add_button.SetBackgroundColour(wx.WHITE)
        add_button.SetBitmap(wx.Image(get_abs_path('ui/resource/add_target.png')).ConvertToBitmap())
        add_button.Bind(wx.EVT_BUTTON, self.add_profile)
        delete_button = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        delete_button.SetToolTip("Delete selected Profile")
        delete_button.SetBackgroundColour(wx.WHITE)
        delete_button.SetBitmap(wx.Image(get_abs_path('ui/resource/delete-target.png')).ConvertToBitmap())
        delete_button.Bind(wx.EVT_BUTTON, self.delete_profile)

        sizer_up = wx.BoxSizer(wx.HORIZONTAL)
        sizer_up.AddStretchSpacer(1)
        sizer_up.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.Add((10, 20))
        sizer_up.Add(self.cbo_port_list, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.Add((20, 20))
        sizer_up.Add(add_button, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.Add((10, 20))
        sizer_up.Add(delete_button, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.AddStretchSpacer(1)

        self.txt_ports = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(400, -1))
        self.show_ports(conf.port_choices[0])
        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(label_title, 0, wx.LEFT | wx.TOP | wx.EXPAND, 10)
        sizer_main.Add(label_tips, 0, wx.ALL, 10)
        sizer_main.Add(label_example, 0, wx.ALL, 10)
        sizer_main.Add(sizer_up, 0, wx.ALL, 10)
        sizer_main.Add(self.txt_ports, 1, wx.ALL, 10)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(sizer_main, 1, wx.EXPAND)
        self.SetSizer(sizer)
        self.Fit()

    def add_profile(self, event):
        dlg = wx.TextEntryDialog(self, 'Enter profile name', 'Create New Profile', '')
        dlg.SetMaxLength(10)

        if dlg.ShowModal() == wx.ID_OK:
            target = dlg.GetValue().strip().replace('_', ' ')
            while target.find('  ') > 0:
                target = target.repalce('  ', ' ')
            is_valid = True
            if not target:
                is_valid = False
                wx.MessageBox('Profile name can not be empty', 'ERROR', wx.ICON_WARNING)
            lower_dict = []
            for item in conf.ports_dict:
                lower_dict.append(item.lower())
            if target.replace(' ', '_').lower() in lower_dict:
                is_valid = False
                wx.MessageBox('Profile name existed, try another name', 'ERROR', wx.ICON_WARNING)
            for c in r'\/:*?"<>|':
                if c in target:
                    is_valid = False
                    wx.MessageBox('Invalid target name', 'ERROR', wx.ICON_WARNING)
            if is_valid:
                self.cbo_port_list.Append([target])
                self.cbo_port_list.SetValue(target)
                self.txt_ports.SetValue('')

        dlg.Destroy()

    def delete_profile(self, event):
        dlg = wx.MessageDialog(self,
                               'About to delete profile [%s]\n'
                               'Data can not be recovered, continue?' % self.cbo_port_list.GetValue(),
                               'Delete Profile',
                               wx.YES_NO | wx.ICON_WARNING)
        if dlg.ShowModal() == wx.ID_YES:
            wx.MessageBox('Port profile [%s] deleted' % self.cbo_port_list.GetValue(), 'Settings', wx.ICON_INFORMATION)
            name = self.cbo_port_list.GetValue().replace(' ', '_')
            config = conf.get_config()
            config.SetPath('ports')
            config.DeleteEntry(name)
            config.Flush()
            conf.load_port_config()
            self.cbo_port_list.Clear()
            for item in conf.port_choices:
                self.cbo_port_list.Append(item)
            self.cbo_port_list.SetValue(conf.port_choices[0])
            self.change_ports(None)
            refresh_cbo_port_list()

    def change_ports(self, event):
        name = self.cbo_port_list.GetValue()
        self.show_ports(name)

    def show_ports(self, name):
        if name.replace(' ', '_') in conf.ports_dict:
            self.txt_ports.SetValue(conf.ports_dict[name.replace(' ', '_')])
        else:
            self.txt_ports.SetValue('')


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    panel = wx.Panel(frame, -1)
    panel_git_hack = PortsProfilePanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
