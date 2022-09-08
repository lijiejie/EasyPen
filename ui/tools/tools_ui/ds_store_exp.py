import wx
import os
import sys
import webbrowser
import subprocess
from lib.common import set_button_img, get_git_hack_folder, get_output_tmp_path, log_output
import lib.config as conf


class DsStoreExpPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        self.SetBackgroundColour(wx.WHITE)

        lbl_description = wx.StaticText(self, -1, 'ds_store_exp is a .DS_Store file disclosure exploit.')
        font = lbl_description.GetFont()
        font.MakeBold()
        lbl_description.SetFont(font)
        lbl_description.SetBackgroundColour((230, 230, 250))
        label = wx.StaticText(self, -1, 'URL')
        self.url = wx.TextCtrl(self, -1, size=(350, -1))
        self.url.SetValue('')
        self.btn_exp = btn_exp = wx.Button(self, -1, "Exploit")
        self.process = None
        btn_exp.Bind(wx.EVT_BUTTON, self.exploit)
        self.Bind(wx.EVT_END_PROCESS, self.on_process_ended)
        set_button_img(btn_exp, os.path.join(conf.root_path, 'ui/resource/brute_start.png'))
        sizer_up = wx.BoxSizer(wx.HORIZONTAL)
        sizer_up.AddStretchSpacer(1)
        sizer_up.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.Add((10, 20))
        sizer_up.Add(self.url, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.Add((20, 20))
        sizer_up.Add(btn_exp, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_up.AddStretchSpacer(1)

        self.result = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(500, -1))
        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(lbl_description, 0, wx.ALL | wx.EXPAND, 10)
        sizer_main.Add(sizer_up, 0, wx.ALL, 10)
        sizer_main.Add(self.result, 1, wx.ALL, 10)

        lbl_url = wx.StaticText(self, -1, 'Docs:  https://github.com/lijiejie/ds_store_exp')
        font = lbl_url.GetFont()
        font.MakeBold()
        lbl_url.SetFont(font)
        lbl_url.SetForegroundColour((72, 118, 255))
        lbl_url.SetCursor(wx.Cursor(wx.CURSOR_HAND))
        lbl_url.Bind(wx.EVT_LEFT_DOWN, self.url_click)
        self.btn_view_files = btn_view_files = wx.Button(self, -1, "View Files")
        btn_view_files.Enable(False)
        btn_view_files.Bind(wx.EVT_BUTTON, self.view_files)

        sizer_down = wx.BoxSizer(wx.HORIZONTAL)
        sizer_down.Add(lbl_url, 0, wx.TOP, 14)
        sizer_down.AddStretchSpacer(1)
        sizer_down.Add(btn_view_files, 0, wx.ALL, 10)
        sizer_main.Add(sizer_down, 0, wx.ALL | wx.EXPAND, 10)

        sizer = wx.BoxSizer()
        sizer.AddStretchSpacer(1)
        sizer.Add(sizer_main, 0, wx.EXPAND)
        sizer.AddStretchSpacer(4)
        self.SetSizer(sizer)
        self.Fit()
        self.Bind(wx.EVT_IDLE, self.on_idle)

    def exploit(self, event):
        if not self.url.GetValue().lower().startswith('http') and self.url.GetValue().find('://') < 0:
            self.url.SetValue('http://' + self.url.GetValue())
        self.domain = get_git_hack_folder(self.url.GetValue().strip())
        self.dest_folder = get_output_tmp_path(self.domain)
        self.url.Enable(False)
        self.btn_exp.Enable(False)
        self.result.Clear()
        log_output('DSStore exploit: %s' % self.url.GetValue())
        self.process = wx.Process(self)
        self.process.Redirect()
        cmd = sys.executable + " " + os.path.join(conf.root_path, "tools/ds_store_exp/ds_store_exp.py ")
        if conf.is_windows_exe:
            cmd = os.path.join(conf.root_path, "tools/ds_store_exp/ds_store_exp.exe ")

        self.pid = wx.Execute(cmd + self.url.GetValue().strip(), wx.EXEC_ASYNC, self.process)

    def on_idle(self, evt):
        if self.process:
            stream = self.process.GetInputStream()
            if stream.CanRead():
                text = stream.read()
                self.result.AppendText(text)

    def on_process_ended(self, event):
        self.process = None
        self.result.AppendText('\nProcess Exited. All files saved to\n' + self.dest_folder)
        self.url.Enable(True)
        if os.path.exists(self.dest_folder):
            self.btn_view_files.Enable(True)
        self.btn_exp.Enable(True)

    def url_click(self, event):
        webbrowser.open_new_tab('https://github.com/lijiejie/ds_store_exp')
        event.Skip()

    def view_files(self, event):
        if os.path.exists(self.dest_folder):
            self.btn_view_files.Enable(False)
            try:
                if sys.platform == 'win32':
                    subprocess.Popen(r'explorer /e,"%s"' % self.dest_folder)
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', self.dest_folder])
                else:
                    subprocess.Popen(['xdg-open', self.dest_folder])
            except Exception as e:
                pass

            self.btn_view_files.Enable(True)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    panel = wx.Panel(frame, -1)
    panel_git_hack = DsStoreExpPanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
