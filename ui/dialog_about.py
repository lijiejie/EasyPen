#!/usr/bin/env python3

import sys

import wx
import wx.html
import wx.lib.wxpTag
import lib.config as conf


class AboutDialog(wx.Dialog):
    text = '''
<html>
<head>
</head>
<body bgcolor="">
<center><table bgcolor="#E6E6FA" width="100%%" cellspacing="0" cellpadding="0" border="0">
<tr>
    <td align="center">
    <h2>EasyPen %s </h2> 
    <span style="color:#191970;font-weight:">Do not use EasyPen for illegal purposes <br />
    This tool is for research only <br />
    Security scan should only be performed on your own hosts <br />
    or for which you were explicitly authorized by its owner <br />
    Use it on your own risk<br /> <br /></span>
    Python Version is: %s
    <br>
    </td>
</tr>
</table>
</center>

<p><b>EasyPen</b> introduced some open source projects <br /><br />
<ol>
<li><span style="color:blue;margin-bottom: 10px;">https://github.com/robertdavidgraham/masscan</span>  @Robert David Graham</li>
<li><span style="color:blue">https://github.com/lijiejie/subDomainsBrute</span>  @lijiejie</li>
<li><span style="color:blue">https://github.com/lijiejie/BBScan</span>  @lijiejie<br /></li>
</ol>
</p>

<p><b>EasyPen</b> contributors <br /><br />
<ol>
<li><span style="color:blue;margin-bottom: 10px;">lijiejie</span>  (https://github.com/lijiejie)</li>
<li><span style="color:blue;margin-bottom: 10px;">wcc526</span>  (https://github.com/wcc526)</li>
<li><span style="color:blue;margin-bottom: 10px;">Shinpachi8</span>  (https://github.com/Shinpachi8)</li>
<li><span style="color:blue;margin-bottom: 10px;">helit</span></li>
</ol>
</p>

<br />
<br />
<center>
<p><wxp module="wx" class="Button">
    <param name="label" value="OK">
    <param name="id"    value="ID_OK">
</wxp></p>
</center>
</body>
</html>
'''

    def __init__(self, parent):
        wx.Dialog.__init__(self, parent, -1, 'About EasyPen',)
        html = wx.html.HtmlWindow(self, -1, size=(600, -1))
        if "gtk2" in wx.PlatformInfo or "gtk3" in wx.PlatformInfo:
            html.SetStandardFonts()
        py_version = sys.version.split()[0]
        txt = self.text % (conf.app_ver, py_version)
        html.SetPage(txt)
        btn = html.FindWindowById(wx.ID_OK)
        ir = html.GetInternalRepresentation()
        html.SetSize((ir.GetWidth()+25, ir.GetHeight()+25))
        self.SetClientSize(html.GetSize())
        self.CentreOnParent(wx.BOTH)


if __name__ == '__main__':
    app = wx.App()
    frame = wx.Frame(None, -1, "My Frame", size=(300, 300))
    frame.Center(wx.BOTH)
    about = AboutDialog(frame)
    about.ShowModal()
    about.Destroy()
    frame.Show()
    app.MainLoop()
