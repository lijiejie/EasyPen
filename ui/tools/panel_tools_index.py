#!/usr/bin/env python3

import wx
import os
import wx.html
import wx.html2
import wx.lib.wxpTag
import lib.config as conf


class ToolIndex(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, size=(500, 500))
        self.SetBackgroundColour('white')

        html = wx.html2.WebView.New(self)
        doc_path = os.path.join(conf.root_path, 'ui/tools/tools.html')
        html.LoadURL('file://' + doc_path)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(html, 1, wx.ALL | wx.EXPAND)
        self.SetSizer(sizer)
        self.Centre(wx.BOTH)
        self.Show()

    def exit(self, event):
        self.Close()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame()
    app.MainLoop()
