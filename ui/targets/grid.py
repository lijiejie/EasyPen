import wx.grid
from lib.common import get_abs_path
from lib.database import DBManager
import lib.config as conf
from lib.event import LogEvent


class TargetGrid(wx.grid.Grid):
    def __init__(self, parent):
        self.results = None
        self.row_count = None
        self.parent = parent
        wx.grid.Grid.__init__(self, parent, -1, size=(600, -1))
        self.created = False
        self.added_rows = 0
        self.added_columns = 0
        self.id_send_selected_items_to_scanner = wx.NewIdRef()
        self.id_send_items_on_page_to_scanner = wx.NewIdRef()
        self.id_send_all_searched_items_to_scanner = wx.NewIdRef()

        self.id_send_selected_items_to_scanner_menu = wx.NewIdRef()
        self.id_send_selected_items_to_scanner_with_domain = wx.NewIdRef()
        self.id_send_selected_items_to_scanner_without_domain = wx.NewIdRef()
        self.id_send_items_on_page_to_scanner_menu = wx.NewIdRef()
        self.id_send_items_on_page_to_scanner_with_domain = wx.NewIdRef()
        self.id_send_items_on_page_to_scanner_without_domain = wx.NewIdRef()
        self.id_send_all_searched_items_to_scanner_menu = wx.NewIdRef()
        self.id_send_all_searched_items_to_scanner_with_domain = wx.NewIdRef()
        self.id_send_all_searched_items_to_scanner_without_domain = wx.NewIdRef()

        self.id_delete_selected_item = wx.NewIdRef()
        self.id_delete_current_page = wx.NewIdRef()
        self.id_delete_searched_all = wx.NewIdRef()
        self.Bind(wx.EVT_MENU, self.send_selected_items_to_scanner, id=self.id_send_selected_items_to_scanner)
        self.Bind(wx.EVT_MENU, self.send_items_on_page_to_scanner, id=self.id_send_items_on_page_to_scanner)
        self.Bind(wx.EVT_MENU, self.send_all_searched_items_to_scanner, id=self.id_send_all_searched_items_to_scanner)

        self.Bind(wx.EVT_MENU, self.send_selected_items_to_scanner_with_domain,
                  id=self.id_send_selected_items_to_scanner_with_domain)
        self.Bind(wx.EVT_MENU, self.send_selected_items_to_scanner,
                  id=self.id_send_selected_items_to_scanner_without_domain)
        self.Bind(wx.EVT_MENU, self.send_items_on_page_to_scanner_with_domain,
                  id=self.id_send_items_on_page_to_scanner_with_domain)
        self.Bind(wx.EVT_MENU, self.send_items_on_page_to_scanner,
                  id=self.id_send_items_on_page_to_scanner_without_domain)
        self.Bind(wx.EVT_MENU, self.send_all_searched_items_to_scanner_with_domain,
                  id=self.id_send_all_searched_items_to_scanner_with_domain)
        self.Bind(wx.EVT_MENU, self.send_all_searched_items_to_scanner,
                  id=self.id_send_all_searched_items_to_scanner_without_domain)

        self.Bind(wx.EVT_MENU, self.delete_selected_item, id=self.id_delete_selected_item)
        self.Bind(wx.EVT_MENU, self.delete_current_page, id=self.id_delete_current_page)
        self.Bind(wx.EVT_MENU, self.delete_searched_all, id=self.id_delete_searched_all)
        self.Bind(wx.EVT_CONTEXT_MENU, self.on_context_menu)

    def on_context_menu(self, event):
        enabled = True if self.row_count != 0 else False
        menu = wx.Menu()

        if self.parent.cbo_table.GetValue() == 'Port':
            sub_menu = wx.Menu()
            sub_menu.Append(self.id_send_selected_items_to_scanner_without_domain, "Without Domains")
            sub_menu.Append(self.id_send_selected_items_to_scanner_with_domain, "With Domains")
            menu.Append(self.id_send_selected_items_to_scanner_menu, "Send Selected Items To Scanner", sub_menu)
            item = menu.FindItemById(self.id_send_selected_items_to_scanner_menu)
            item.SetBitmap(wx.Image(get_abs_path('ui/resource/send_to_scanner.png')).ConvertToBitmap())
            item.Enable(enabled)

            sub_menu = wx.Menu()
            sub_menu.Append(self.id_send_items_on_page_to_scanner_without_domain, "Without Domains")
            sub_menu.Append(self.id_send_items_on_page_to_scanner_with_domain, "With Domains")
            menu.Append(self.id_send_items_on_page_to_scanner_menu, "Send Items On This Page To Scanner", sub_menu)
            item = menu.FindItemById(self.id_send_items_on_page_to_scanner_menu)
            item.Enable(enabled)

            sub_menu = wx.Menu()
            sub_menu.Append(self.id_send_all_searched_items_to_scanner_without_domain, "Without Domains")
            sub_menu.Append(self.id_send_all_searched_items_to_scanner_with_domain, "With Domains")
            menu.Append(self.id_send_all_searched_items_to_scanner_menu,
                        "Send All Search Result Items To Scanner", sub_menu)
            item = menu.FindItemById(self.id_send_all_searched_items_to_scanner_menu)
            item.Enable(enabled)

        else:
            item = wx.MenuItem(menu, self.id_send_selected_items_to_scanner, "Send Selected Items To Scanner")
            item.SetBitmap(wx.Image(get_abs_path('ui/resource/send_to_scanner.png')).ConvertToBitmap())
            menu.Append(item)
            item.Enable(enabled)
            item = wx.MenuItem(menu, self.id_send_items_on_page_to_scanner, "Send Items On This Page To Scanner")
            menu.Append(item)
            item.Enable(enabled)
            item = wx.MenuItem(menu, self.id_send_all_searched_items_to_scanner,
                               "Send All Search Result Items To Scanner")
            menu.Append(item)
            item.Enable(enabled)

        menu.AppendSeparator()
        item = wx.MenuItem(menu, self.id_delete_selected_item, "Delete Selected Items")
        menu.Append(item)
        item.SetBitmap(wx.Image(get_abs_path('ui/resource/menu_delete_target.png')).ConvertToBitmap())
        item.Enable(enabled)
        item = wx.MenuItem(menu, self.id_delete_current_page, "Delete All Items On This Page")
        menu.Append(item)
        item.Enable(enabled)
        item = wx.MenuItem(menu, self.id_delete_searched_all, "Delete All Search Result Items")
        menu.Append(item)
        item.Enable(enabled)

        self.PopupMenu(menu)
        menu.Destroy()

    def send_selected_items_to_scanner_with_domain(self, event):
        self.send_selected_items_to_scanner(None, process_domain=True)

    def send_items_on_page_to_scanner_with_domain(self, event):
        self.send_items_on_page_to_scanner(None, process_domain=True)

    def send_all_searched_items_to_scanner_with_domain(self, event):
        self.send_all_searched_items_to_scanner(None, process_domain=True)

    def send_selected_items_to_scanner(self, event, process_domain=False):
        if conf.main_frame.scan_panel.scan_box.btn_scan.GetLabel() == 'Stop':
            wx.MessageBox('Scanner is busy now', "EasyPen", wx.ICON_WARNING)
            return
        if len(list(self.GetSelectedBlocks())) == 0:
            wx.MessageBox('No item was selected', "EasyPen", wx.ICON_WARNING)
            return
        db_name = self.parent.cbo_databases.GetValue()
        table_name = self.parent.cbo_table.GetValue()
        targets_input = ''
        if db_name == "All DB":
            if table_name in ['Domain', 'IP']:
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 2) + '\n'
            elif table_name == 'Port':
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 4) + '://' + \
                                 self.GetCellValue(row, 2) + ':' + self.GetCellValue(row, 3) + '\n'
                        if process_domain and self.GetCellValue(row, 7).strip():
                            domains = self.GetCellValue(row, 7).strip().split(',')
                            for domain in domains:
                                targets_input += self.GetCellValue(row, 4) + '://' + \
                                                 domain + ':' + self.GetCellValue(row, 3) + '\n'

            elif table_name == 'Vulnerability':
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 4) + '://' + \
                                 self.GetCellValue(row, 5) + ':' + self.GetCellValue(row, 6) + '\n'
        else:
            if table_name in ['Domain', 'IP']:
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 1) + '\n'
            elif table_name == 'Port':
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 3) + '://' + \
                                 self.GetCellValue(row, 1) + ':' + self.GetCellValue(row, 2) + '\n'
                        if process_domain and self.GetCellValue(row, 6).strip():
                            domains = self.GetCellValue(row, 6).strip().split(',')
                            for domain in domains:
                                targets_input += self.GetCellValue(row, 3) + '://' + \
                                                 domain + ':' + self.GetCellValue(row, 2) + '\n'
            elif table_name == 'Vulnerability':
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        targets_input += self.GetCellValue(row, 3) + '://' + \
                                 self.GetCellValue(row, 4) + ':' + self.GetCellValue(row, 5) + '\n'
        conf.main_frame.scan_panel.scan_box.txt_targets.SetValue(targets_input)
        conf.main_frame.scan_panel.scan_box.chk_port_scan.SetValue(table_name in ['Domain', 'IP'])
        conf.main_frame.notebook.SetSelection(2)
        conf.main_frame.statusBar.SetStatusText('Send %s items to scanner' % targets_input.count('\n'))

    def send_items_on_page_to_scanner(self, event, process_domain=False):
        if conf.main_frame.scan_panel.scan_box.btn_scan.GetLabel() == 'Stop':
            wx.MessageBox('Scanner is busy now', "EasyPen", wx.ICON_WARNING)
            return
        db_name = self.parent.cbo_databases.GetValue()
        table_name = self.parent.cbo_table.GetValue()
        targets_input = ''
        if db_name == "All DB":
            for row in range(0, self.row_count):
                if table_name in ['Domain', 'IP']:
                    targets_input += self.GetCellValue(row, 2) + '\n'
                elif table_name == 'Port':
                    targets_input += self.GetCellValue(row, 4) + '://' + \
                                     self.GetCellValue(row, 2) + ':' + self.GetCellValue(row, 3) + '\n'
                    if process_domain and self.GetCellValue(row, 7).strip():
                        domains = self.GetCellValue(row, 7).strip().split(',')
                        for domain in domains:
                            targets_input += self.GetCellValue(row, 4) + '://' + \
                                             domain + ':' + self.GetCellValue(row, 3) + '\n'

                elif table_name == 'Vulnerability':
                    targets_input += self.GetCellValue(row, 4) + '://' + \
                                     self.GetCellValue(row, 5) + ':' + self.GetCellValue(row, 6) + '\n'
        else:
            for row in range(0, self.row_count):
                if table_name in ['Domain', 'IP']:
                    targets_input += self.GetCellValue(row, 1) + '\n'
                elif table_name == 'Port':
                    targets_input += self.GetCellValue(row, 3) + '://' + \
                                     self.GetCellValue(row, 1) + ':' + self.GetCellValue(row, 2) + '\n'
                    if process_domain and self.GetCellValue(row, 6).strip():
                        domains = self.GetCellValue(row, 6).strip().split(',')
                        for domain in domains:
                            targets_input += self.GetCellValue(row, 3) + '://' + \
                                             domain + ':' + self.GetCellValue(row, 2) + '\n'
                elif table_name == 'Vulnerability':
                    targets_input += self.GetCellValue(row, 3) + '://' + \
                                     self.GetCellValue(row, 4) + ':' + self.GetCellValue(row, 5) + '\n'
        conf.main_frame.scan_panel.scan_box.txt_targets.SetValue(targets_input)
        conf.main_frame.scan_panel.scan_box.chk_port_scan.SetValue(table_name in ['Domain', 'IP'])
        conf.main_frame.notebook.SetSelection(2)
        conf.main_frame.statusBar.SetStatusText('Send %s items to scanner' % targets_input.count('\n'))

    def send_all_searched_items_to_scanner(self, event, process_domain=False):
        if conf.main_frame.scan_panel.scan_box.btn_scan.GetLabel() == 'Stop':
            wx.MessageBox('Scanner is busy now', "EasyPen", wx.ICON_WARNING)
            return
        table_name = self.parent.cbo_table.GetValue()
        self.parent.send_search_result_all_items(process_domain)
        conf.main_frame.scan_panel.scan_box.chk_port_scan.SetValue(table_name in ['Domain', 'IP'])
        conf.main_frame.notebook.SetSelection(2)

    def delete_selected_item(self, event):
        if len(list(self.GetSelectedBlocks())) == 0:
            wx.MessageBox('No item was selected', "EasyPen", wx.ICON_WARNING)
        else:
            db_name = self.parent.cbo_databases.GetValue()
            items = {}
            if db_name == "All DB":
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        _db_name = self.GetCellValue(row, 0)
                        if _db_name not in items:
                            items[_db_name] = []
                        items[_db_name].append(self.GetCellValue(row, 1))
            else:
                ids = []
                for item in self.GetSelectedBlocks():
                    for row in range(item.TopRow, item.BottomRow+1):
                        ids.append(self.GetCellValue(row, 0))
                items[db_name] = ids
            count = 0
            for db_name in items:
                count += len(items[db_name])
            dlg = wx.MessageDialog(self,
                                   'About to delete %s items\n'
                                   'Data can not be recovered, continue?' % count,
                                   'Delete Item',
                                   wx.YES_NO | wx.ICON_WARNING)
            if dlg.ShowModal() == wx.ID_YES:
                self.delete_items(items)

    def delete_items(self, items):
        for db_name in items:
            db_manager = DBManager(db_name)
            table = self.parent.cbo_table.GetValue()
            if table == "Domain":
                for domain_id in items[db_name]:
                    db_manager.cursor.execute('delete from domain where id = ?', (int(domain_id),))
                    db_manager.cursor.execute('delete from domain_ips where domain_id = ?', (int(domain_id),))
            elif table == 'IP':
                for ip_id in items[db_name]:
                    db_manager.cursor.execute('delete from ip where id = ?', (int(ip_id),))
                    db_manager.cursor.execute('delete from domain_ips where ip_id = ?', (int(ip_id),))
            elif table == 'Port':
                for port_id in items[db_name]:
                    db_manager.cursor.execute('delete from port where id = ?', (int(port_id),))
            elif table == 'Vulnerability':
                for vul_id in items[db_name]:
                    db_manager.cursor.execute('delete from vulnerability where id = ?', (int(vul_id),))
            db_manager.commit()
            db_manager.close_db()
            wx.PostEvent(conf.main_frame.target_tree, LogEvent(refresh=db_name))
        self.parent.do_search(None, page=self.parent.cur_page)

    def delete_current_page(self, event):
        db_name = self.parent.cbo_databases.GetValue()
        items = {}
        if db_name == "All DB":
            for row in range(0, self.row_count):
                _db_name = self.GetCellValue(row, 0)
                if _db_name not in items:
                    items[_db_name] = []
                items[_db_name].append(self.GetCellValue(row, 1))
        else:
            ids = []
            for row in range(0, self.row_count):
                ids.append(self.GetCellValue(row, 0))
            items[db_name] = ids
        count = 0
        for db_name in items:
            count += len(items[db_name])
        dlg = wx.MessageDialog(self,
                               'About to delete %s items\n'
                               'Data can not be recovered, continue?' % count,
                               'Delete Item',
                               wx.YES_NO | wx.ICON_WARNING)
        if dlg.ShowModal() == wx.ID_YES:
            self.delete_items(items)

    def delete_searched_all(self, event):
        self.parent.delete_search_result_all_items()

    def show_data(self, results, column_names):
        self.results = results
        self.Freeze()
        len_rows = len(results)
        len_columns = len(column_names)

        if not self.created:
            self.created = True
            self.CreateGrid(len_rows, len_columns)
            self.added_rows = len_rows
            self.added_columns = len_columns
        else:

            if len_columns > self.added_columns:
                self.AppendCols(len_columns - self.added_columns)
            elif len_columns < self.added_columns:
                self.DeleteCols(numCols=self.added_columns - len_columns)
            self.added_columns = len_columns

            if len_rows > self.added_rows:
                self.AppendRows(len_rows - self.added_rows)
            elif len_rows < self.added_rows:
                self.DeleteRows(numRows=self.added_rows - len_rows)
            self.added_rows = len_rows
            self.ClearGrid()

        for i in range(len_columns):
            self.SetColLabelValue(i, column_names[i])
            self.SetColLabelAlignment(wx.ALIGN_LEFT, -1)

        self.SetRowLabelSize(0)

        row_num = 0
        for item in results:
            for col_num in range(len_columns):
                if item[col_num]:
                    self.SetCellValue(row_num, col_num, str(item[col_num]))
                else:
                    self.SetCellValue(row_num, col_num, "")
            row_num += 1
        self.row_count = row_num
        self.AutoSize()
        self.Layout()
        self.parent.Layout()
        self.Thaw()

