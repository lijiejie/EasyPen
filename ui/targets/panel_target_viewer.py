import random
import wx
import wx.lib.newevent
import lib.config as conf
from lib.common import get_abs_path, get_output_tmp_path
from lib.database import DBManager
from ui.targets.grid import TargetGrid
from ui.targets.sql import SQLGenerator
from lib.event import LogEvent


class DBViewPanel(wx.Panel):
    def __init__(self, frame):
        if hasattr(frame, 'notebook'):
            wx.Panel.__init__(self, frame.notebook, -1, style=wx.CLIP_CHILDREN)
        else:
            wx.Panel.__init__(self, frame, -1, style=wx.CLIP_CHILDREN)

        self.frame = frame
        self.grid = TargetGrid(self)
        target_tree_list = conf.target_tree_list
        # val = target_tree_list[0][0] if target_tree_list else ''
        databases = [x[0] for x in target_tree_list]
        databases.insert(0, "All DB")
        self.cbo_databases = wx.ComboBox(self, -1, "All DB", size=(130, -1),
                                         choices=databases,
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.cbo_table = wx.ComboBox(self, -1, "Port", size=(100, -1),
                                     choices=["Port", "Domain", "IP", "Vulnerability"],
                                     style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.keyword = wx.SearchCtrl(self, style=wx.TE_PROCESS_ENTER, size=(220, -1))
        self.keyword.ShowCancelButton(True)
        self.keyword.Bind(wx.EVT_SEARCH, self.do_search)
        self.keyword.Bind(wx.EVT_CHAR_HOOK, self.do_empty_enter)
        self.keyword.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN, self.clear_keyword)
        self.btn_search = wx.Button(self, -1, "Search")
        self.btn_search.Bind(wx.EVT_BUTTON, self.do_search)

        search_sizer = wx.BoxSizer(wx.HORIZONTAL)

        search_sizer.Add(self.cbo_databases, 0, wx.ALL, 2)
        search_sizer.Add(self.cbo_table, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        search_sizer.Add(self.keyword, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        search_sizer.Add(self.btn_search, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)

        self.button_last = button_last = wx.Button(self, -1, "Previous Page", size=(-1, 24), style=wx.NO_BORDER)
        button_last.SetToolTip("Goto Previous Page")
        button_last.SetBackgroundColour(wx.WHITE)
        button_last.SetBitmap(wx.Image(get_abs_path('ui/resource/page_previous.png')).ConvertToBitmap())
        button_last.Bind(wx.EVT_BUTTON, self.go_last_page)

        self.button_next = button_next = wx.Button(self, -1, "Next Page", size=(-1, 24), style=wx.NO_BORDER)
        button_next.SetToolTip("Goto Next Page")
        button_next.SetBackgroundColour(wx.WHITE)
        button_next.SetBitmap(wx.Image(get_abs_path('ui/resource/page_next.png')).ConvertToBitmap())
        button_next.SetBitmapPosition(wx.RIGHT)
        button_next.Bind(wx.EVT_BUTTON, self.go_next_page)

        lbl_page = wx.StaticText(self, -1, "Page", style=wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        self.page_num = wx.TextCtrl(self, -1, size=(80, -1), style=wx.TE_PROCESS_ENTER)
        self.page_num.Bind(wx.EVT_TEXT_ENTER, self.go_any_page)
        self.button_go_page = button_go_page = wx.Button(self, -1, "Go", size=(40, -1))
        button_go_page.SetToolTip("Goto Any Page")
        button_go_page.Bind(wx.EVT_BUTTON, self.go_any_page)
        self.lbl_page_total = wx.StaticText(self, -1, "", style=wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)

        self.lbl_search_result = wx.StaticText(self, -1, "", style=wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        bottom_sizer = wx.BoxSizer(wx.HORIZONTAL)
        bottom_sizer.Add(button_last)
        bottom_sizer.Add((20, -1))
        bottom_sizer.Add(button_next)
        bottom_sizer.Add(lbl_page, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 30)
        bottom_sizer.Add(self.page_num, 0, wx.LEFT, 5)
        bottom_sizer.Add(self.lbl_page_total, 0, wx.ALIGN_CENTER_VERTICAL)
        bottom_sizer.Add(button_go_page, 0, wx.LEFT, 10)

        bottom_sizer.AddStretchSpacer(1)
        bottom_sizer.Add(self.lbl_search_result, 0, wx.ALIGN_CENTER_VERTICAL)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(search_sizer, 0, wx.ALL, 10)
        sizer.Add(self.grid, 1, wx.EXPAND | wx.ALL, 10)
        sizer.Add(bottom_sizer, 0, wx.EXPAND | wx.ALL, 2)

        self.SetSizer(sizer)
        self.cur_page = None
        self.total_pages = None

    def go_last_page(self, event):
        if self.cur_page > 1:
            self.do_search(None, page=self.cur_page - 1)
        event.Skip()

    def go_next_page(self, event):
        if self.cur_page < self.total_pages:
            self.do_search(None, page=self.cur_page + 1)
        event.Skip()

    def go_any_page(self, event):
        try:
            page = int(self.page_num.GetValue())
            if 1 <= page <= self.total_pages:
                self.do_search(None, page=page)
        except Exception as e:
            pass
        event.Skip()

    def refresh_cbo_databases(self):
        old_value = self.cbo_databases.GetValue()
        self.cbo_databases.Clear()
        databases = [x[0] for x in conf.target_tree_list]
        databases.insert(0, "All DB")
        for db in databases:
            self.cbo_databases.Append(db)
        if old_value in databases:
            self.cbo_databases.SetValue(old_value)
        else:
            self.cbo_databases.SetValue("All DB")
            self.do_search(None)

    def do_empty_enter(self, event):
        if hasattr(event, "KeyCode"):
            if event.KeyCode == 13 and not self.keyword.GetValue():
                self.do_search(None)
        event.Skip()

    def clear_keyword(self, event):
        self.keyword.SetValue('')
        self.do_search(event)

    def do_search(self, event, page=1):
        page_size = conf.targets_display_pagesize
        self.cur_page = None
        self.total_pages = None
        cbo_db = self.cbo_databases.GetValue()
        if cbo_db == 'All DB':
            selected_dbs = [x[0] for x in conf.target_tree_list]
        else:
            selected_dbs = [cbo_db.strip()]

        table_name = self.cbo_table.GetValue().lower()
        keyword = self.keyword.GetValue().strip() if self.keyword.GetValue() else ''

        self.cur_page = page    # show one page only
        matched_count_in_all_db = 0
        should_skipped_total = (page - 1) * page_size
        already_skipped_count = 0
        """
        search all db with keyword and concat all matched results
        """
        returned_count = 0
        results = []
        column_names = None
        for db_name in selected_dbs:
            db_manager = DBManager(db_name)
            generator = SQLGenerator(table_name, keyword)
            db_manager.cursor.execute(generator.count_sql)
            matched_count = int(db_manager.cursor.fetchone()[0])
            matched_count_in_all_db += matched_count

            # not yet skipped enough items, do not fetch data from this db
            # we can get column names now
            if already_skipped_count + matched_count <= should_skipped_total:
                already_skipped_count += matched_count
                if not column_names:
                    sql = generator.fetch_sql + ' limit 1'
                    db_manager.cursor.execute(sql)
                    db_manager.cursor.fetchall()
                    column_names = [description[0] for description in db_manager.cursor.description]
                    if cbo_db == 'All DB':
                        column_names.insert(0, "Database")
                db_manager.close_db()
                continue
            # how many more items should be skipped
            # there must be some items left for results display
            offset = should_skipped_total - already_skipped_count
            # the first fetch will meet skip count, later offset will become 0
            already_skipped_count = should_skipped_total

            if returned_count + matched_count - offset <= page_size:
                # there are no enough items to fill results
                # so limit x has no effects
                sql = generator.fetch_sql + ' limit %s offset %s' % (int(page_size - returned_count), offset)
                db_manager.cursor.execute(sql)
                returned_count += matched_count - offset

                if cbo_db == 'All DB':
                    for item in db_manager.cursor.fetchall():
                        results.append((db_name,) + item)
                else:
                    results += db_manager.cursor.fetchall()

            elif returned_count < page_size:
                sql = generator.fetch_sql + ' limit %s offset %s' % (int(page_size - returned_count), offset)
                db_manager.cursor.execute(sql)
                if cbo_db == 'All DB':
                    for item in db_manager.cursor.fetchall():
                        results.append((db_name,) + item)
                else:
                    results += db_manager.cursor.fetchall()
                returned_count = page_size

            if not column_names:
                column_names = [description[0] for description in db_manager.cursor.description]
                if cbo_db == 'All DB':
                    column_names.insert(0, "Database")
            db_manager.close_db()

        self.lbl_search_result.SetLabelText('Display %s out of %s' % (len(results), matched_count_in_all_db))
        self.page_num.SetValue(str(self.cur_page))
        self.total_pages = int(matched_count_in_all_db / page_size)
        if matched_count_in_all_db % page_size != 0:
            self.total_pages += 1
        self.lbl_page_total.SetLabelText(' / %s' % str(self.total_pages))
        self.grid.show_data(results, column_names)
        self.update_page_button()

    def delete_search_result_all_items(self):
        cbo_db = self.cbo_databases.GetValue()
        if cbo_db == 'All DB':
            selected_dbs = [x[0] for x in conf.target_tree_list]
        else:
            selected_dbs = [cbo_db.strip()]

        table_name = self.cbo_table.GetValue().lower()
        keyword = self.keyword.GetValue().strip() if self.keyword.GetValue() else ''

        matched_count_in_all_db = 0
        for db_name in selected_dbs:
            db_manager = DBManager(db_name)
            generator = SQLGenerator(table_name, keyword)
            db_manager.cursor.execute(generator.count_sql)
            matched_count = int(db_manager.cursor.fetchone()[0])
            matched_count_in_all_db += matched_count
            db_manager.close_db()

        dlg = wx.MessageDialog(self,
                               'About to delete %s items\n'
                               'Data can not be recovered, continue?' % matched_count_in_all_db,
                               'Delete Item',
                               wx.YES_NO | wx.ICON_WARNING)
        if dlg.ShowModal() == wx.ID_YES:
            for db_name in selected_dbs:
                db_manager = DBManager(db_name)
                generator = SQLGenerator(table_name, keyword)
                db_manager.cursor.execute(generator.delete_sql)
                db_manager.commit()
                # do some clean
                if table_name == 'domain':
                    db_manager.cursor.execute('delete from domain_ips where domain_id not in'
                                              ' (select DISTINCT id from domain)')
                    db_manager.commit()
                if table_name == 'ip':
                    db_manager.cursor.execute('delete from domain_ips where ip_id not in'
                                              ' (select DISTINCT id from ip)')
                    db_manager.commit()
                db_manager.close_db()
                wx.PostEvent(conf.main_frame.target_tree, LogEvent(refresh=db_name))
            self.do_search(None)

    def send_search_result_all_items(self, process_domain=False):
        cbo_db = self.cbo_databases.GetValue()
        if cbo_db == 'All DB':
            selected_dbs = [x[0] for x in conf.target_tree_list]
        else:
            selected_dbs = [cbo_db.strip()]

        table_name = self.cbo_table.GetValue().lower()
        keyword = self.keyword.GetValue().strip() if self.keyword.GetValue() else ''

        matched_count_in_all_db = 0
        for db_name in selected_dbs:
            db_manager = DBManager(db_name)
            generator = SQLGenerator(table_name, keyword)
            db_manager.cursor.execute(generator.count_sql)
            matched_count = int(db_manager.cursor.fetchone()[0])
            matched_count_in_all_db += matched_count
            db_manager.close_db()

        targets_input = ''
        to_box = True if matched_count_in_all_db <= 1000 else False
        out_file = None
        if not to_box:
            out_file_path = get_output_tmp_path('targets_input_%s.txt' % round(random.random(), 3))
            out_file = open(out_file_path, 'w')

        for db_name in selected_dbs:
            db_manager = DBManager(db_name)
            generator = SQLGenerator(table_name, keyword)
            db_manager.cursor.execute(generator.fetch_sql)
            ret = db_manager.cursor.fetchall()
            for item in ret:
                if table_name in ['domain', 'ip']:
                    if to_box:
                        targets_input += item[1] + '\n'
                    else:
                        out_file.write(item[1] + '\n')

                if table_name == 'port':
                    if to_box:
                        targets_input += '%s://%s:%s\n' % (item[3], item[1], item[2])
                    else:
                        out_file.write('%s://%s:%s\n' % (item[3], item[1], item[2]))
                    if process_domain and item[6] and item[6].strip():
                        domains = item[6].strip().split(',')
                        for domain in domains:
                            if to_box:
                                targets_input += '%s://%s:%s\n' % (item[3], domain, item[2])
                            else:
                                out_file.write('%s://%s:%s\n' % (item[3], domain, item[2]))
                            matched_count_in_all_db += 1
                if table_name == 'vulnerability':
                    if to_box:
                        targets_input += '%s://%s:%s\n' % (item[3], item[4], item[5])
                    else:
                        out_file.write('%s://%s:%s\n' % (item[3], item[4], item[5]))
            db_manager.close_db()

        if to_box:
            conf.main_frame.scan_panel.scan_box.txt_targets.SetValue(targets_input)
        else:
            out_file.close()
            conf.main_frame.scan_panel.scan_box.files_to_import = [out_file_path]
            conf.main_frame.scan_panel.scan_box.txt_targets.SetValue(
                'Import targets from file\nDouble click to clear\n\n' + out_file_path)
            conf.main_frame.scan_panel.scan_box.txt_targets.SetEditable(False)

        conf.main_frame.statusBar.SetStatusText('Send %s items to scanner' % matched_count_in_all_db)

    def update_page_button(self):
        if self.cur_page == 1:
            self.button_last.Enable(False)
        else:
            self.button_last.Enable(True)

        if self.cur_page >= self.total_pages:
            self.button_next.Enable(False)
        else:
            self.button_next.Enable(True)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 500))

    from lib.database import get_db_statistics
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
    win = DBViewPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
