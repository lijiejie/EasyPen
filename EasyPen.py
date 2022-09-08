#!/bin/env python3
"""
  EasyPen is a GUI program which helps pentesters do information gathering, vulnerability scan and exploitation.

  It has more than 100 built-in scan scripts written in Python which covers most common vulnerabilities
  while at the same time
  it provides you some extra exploitation tools.

  You can easily write your own python script and init scan for thousands of targets.

  Created By: Li JieJie    https://github.com/lijiejie/EasyPen
"""

import wx
import lib.config as conf
import wx.lib.mixins.inspection


class ScannerApp(wx.App, wx.lib.mixins.inspection.InspectionMixin):
    def OnInit(self):
        self.InitInspection()
        wx.SystemOptions.SetOption("mac.window-plain-transition", 1)
        self.SetAppName("EasyPen")
        conf.load_config()
        conf.init_logging()
        if conf.user_agreement_accepted == conf.app_ver:
            from ui.frame_loading import LoadingFrame
            splash = LoadingFrame()
            splash.Show()
        else:
            from ui.frame_agreement import AgreementFrame
            frame = AgreementFrame()
            frame.Show()

        return True

    def InitLocale(self):
        # do nothing if wx version is 4.2.0
        ver = wx.VERSION
        if ver[0] == 4 and ver[1] == 2 and ver[2] == 0 and 'wxMSW' in wx.PlatformInfo:
            return
        self.ResetLocale()
        if 'wxMSW' in wx.PlatformInfo:
            import locale
            try:
                lang, enc = locale.getdefaultlocale()
                self._initial_locale = wx.Locale(lang, lang[:2], lang)
                locale.setlocale(locale.LC_ALL, lang)
            except (ValueError, locale.Error) as ex:
                pass


if __name__ == '__main__':
    app = ScannerApp(False)
    app.MainLoop()
