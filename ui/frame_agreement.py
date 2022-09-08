#!/usr/bin/env python3

import wx
import os
import wx.html
import wx.html2
import wx.lib.wxpTag
import lib.config as conf


class AgreementFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, "User Agreement", size=(500, 500),
                          style=wx.DEFAULT_FRAME_STYLE & ~wx.RESIZE_BORDER & ~wx.MAXIMIZE_BOX)
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image(os.path.join(conf.root_path, 'ui/resource/EasyPen.png')).ConvertToBitmap())
        self.SetIcon(icon)
        self.SetBackgroundColour('white')

        html = wx.html2.WebView.New(self)
        doc_path = os.path.join(conf.root_path, 'ui/agreement.html')
        html.LoadURL('file://' + doc_path)

        btn_exit = wx.Button(self, -1, 'Exit')
        btn_exit.Bind(wx.EVT_BUTTON, self.exit)
        self.chk_accept = chk_accept = wx.CheckBox(self, -1, "I understand and accept all terms")
        chk_accept.Bind(wx.EVT_CHECKBOX, self.on_accept_check)
        self.btn_ok = btn_ok = wx.Button(self, -1, 'Enter')
        btn_ok.Bind(wx.EVT_BUTTON, self.enter)
        btn_ok.Enable(False)
        bottom_sizer = wx.BoxSizer(wx.HORIZONTAL)
        bottom_sizer.Add((2, 2), 1, wx.EXPAND)
        bottom_sizer.Add(btn_exit, 0, wx.ALL, 10)
        bottom_sizer.Add((20, 10), 0, wx.ALL, 10)
        bottom_sizer.Add(chk_accept, 0, wx.TOP | wx.BOTTOM, 15)
        bottom_sizer.Add(btn_ok, 0, wx.ALL, 10)
        bottom_sizer.Add((2, 2), 1, wx.EXPAND)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.ALL | wx.EXPAND)
        sizer.Add(bottom_sizer, 0, wx.ALL | wx.EXPAND, 10)
        self.SetSizer(sizer)
        self.Centre(wx.BOTH)
        self.Show()

    def exit(self, event):
        self.Close()

    def on_accept_check(self, event):
        self.btn_ok.Enable(self.chk_accept.GetValue())

    def enter(self, event):
        config = conf.get_config()
        config.SetPath('agreement')
        config.Write('UserAgreeMentAccepted', conf.app_ver)
        config.Flush()
        self.Hide()
        from ui.frame_loading import LoadingFrame
        splash = LoadingFrame()
        splash.Show()
        self.Destroy()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = AgreementFrame()
    app.MainLoop()
