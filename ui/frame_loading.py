import wx
import os
from wx.adv import SplashScreen
from ui.frame_main import MainFrame
import lib.config as conf
from lib.database import create_database, get_db_statistics
from lib.common import log_output


def init_app():
    # create database folder if not existed
    db_folder = os.path.join(conf.root_path, 'database')
    if not os.path.exists(db_folder):
        os.makedirs(db_folder)

    # no database found, create default db
    folder_count = 0
    for item in os.listdir(db_folder):
        if os.path.isdir(os.path.join(db_folder, item)):
            folder_count += 1
    if folder_count == 0:
        create_database('default')

    # read db info
    statistics = get_db_statistics()
    for target in statistics:
        item = statistics[target]
        conf.target_tree_list.append(
            (target, [
                'Domain (%s)' % item.get('domain', 0),
                'IP (%s)' % item.get('ip', 0),
                'Port (%s)' % item.get('port', 0),
                'Vulnerability (%s)' % item.get('vulnerability', 0),
                'URL (%s)' % item.get('url', 0),
                ])
        )


class LoadingFrame(SplashScreen):
    def __init__(self):
        bmp = wx.Image("ui/resource/loading.jpg").ConvertToBitmap()
        SplashScreen.__init__(self, bmp, wx.adv.SPLASH_CENTRE_ON_SCREEN | wx.adv.SPLASH_TIMEOUT, 1000, None, -1)
        self.Bind(wx.EVT_CLOSE, self.on_close)
        init_app()

    def on_close(self, evt):
        self.Hide()
        frame = MainFrame(None, "EasyPen %s" % conf.app_ver)
        frame.Show()
        frame.Raise()
        log_output('EasyPen %s start, wxpython version is %s' % (conf.app_ver, wx.version()))
        evt.Skip()
