#!/usr/bin/env python3

import wx
import os
import lib.config as conf


class ScanResultViewFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, None, -1, "Vulnerability Details", size=(500, 200),
                          style=wx.DEFAULT_FRAME_STYLE & ~wx.RESIZE_BORDER & ~wx.MAXIMIZE_BOX | wx.STAY_ON_TOP)
        self.parent = parent
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image(os.path.join(conf.root_path, 'ui/resource/EasyPen.png')).ConvertToBitmap())
        self.SetIcon(icon)
        self.SetBackgroundColour('white')
        self.text = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE | wx.HSCROLL | wx.TE_RICH2 | wx.TE_NOHIDESEL)

    def show_details(self, details):
        self.text.SetValue(details)
        self.text.SetEditable(False)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = ScanResultViewFrame(None)
    frame.Show()
    app.MainLoop()
