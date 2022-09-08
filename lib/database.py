import os
import sqlite3
import shutil
import time
import wx
from lib.common import now_time, is_intranet, log_output
from lib.config import root_path


class DBManager(object):
    def __init__(self, db_name):
        self.db_conn = sqlite3.connect(os.path.join(root_path, 'database/%s/data.db' % db_name.strip()))
        self.cursor = self.db_conn.cursor()

    def close_db(self):
        self.db_conn.close()

    def commit(self):
        while True:
            try:
                self.db_conn.commit()
                break
            except Exception as e:
                log_output("DB commit failed: %s, try again 1 second later" % str(e))
                time.sleep(1.0)

    def insert_or_update_domain(self, domain):
        insert_count = update_count = 0
        self.cursor.execute("select id from domain where name = ? ", (domain,))
        ret = self.cursor.fetchone()
        t = now_time()
        if ret:
            domain_id = ret[0]
            self.cursor.execute("update domain set updated_time=? where id= ? ", (t, domain_id))
            self.commit()
            update_count = 1
        else:
            self.cursor.execute("INSERT INTO domain (name, created_time, updated_time) "
                                "VALUES (?, ?, ?) ", (domain, t, t))
            self.commit()
            insert_count = 1
            domain_id = self.cursor.lastrowid
        return domain_id, insert_count, update_count

    def insert_or_update_ip(self, ip_addr, domain_id=None):
        insert_count = 0
        ip_addr = ip_addr.strip()
        self.cursor.execute("select id from ip where ip_addr = ? ", (ip_addr,))
        ret = self.cursor.fetchone()
        t = now_time()
        if ret:
            ip_id = ret[0]
        else:
            insert_count = 1
            self.cursor.execute("INSERT INTO ip (ip_addr, is_intra_net, created_time, updated_time) "
                                "VALUES (?, ?, ?, ?) ", (ip_addr, is_intranet(ip_addr), t, t))
            self.commit()
            ip_id = self.cursor.lastrowid
        # update table: Domain -> IP
        if domain_id:
            self.cursor.execute("select * from domain_ips where domain_id=? and ip_id=? ", (domain_id, ip_id))
            ret = self.cursor.fetchone()
            if ret:
                self.cursor.execute("update domain_ips set updated_time=? where domain_id=? and ip_id = ? ",
                                    (t, domain_id, ip_id))
                self.commit()
            else:
                self.cursor.execute("INSERT INTO domain_ips (domain_id, ip_id, updated_time) "
                                    "VALUES (?, ?, ?) ", (domain_id, ip_id, t))
                self.commit()
        return ip_id, insert_count

    def get_ip_id(self, ip_addr):
        self.cursor.execute("select * from ip where ip_addr=?", (ip_addr,))
        ret = self.cursor.fetchone()
        return ret[0] if ret else -1

    def insert_or_update_port(self, port_no, ip_id, service_name, service_version, is_http):
        insert_count = update_count = 0
        self.cursor.execute("select * from port where port_no=? and ip_id=?", (port_no, ip_id))
        ret = self.cursor.fetchone()
        t = now_time()
        if ret:
            update_count += 1
            self.cursor.execute("update port set service_name=?, service_version=?, is_http=?, "
                                "updated_time=? where id=?",
                                (service_name, service_version, is_http, t, ret[0]))
        else:
            insert_count += 1
            self.cursor.execute(
                "INSERT INTO port (port_no, ip_id, service_name, service_version, is_http, created_time, updated_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ",
                (port_no, ip_id, service_name, service_version, is_http, t, t))
        self.commit()
        return insert_count, update_count

    def insert_or_update_vul(self, vul):
        insert_count = update_count = 0
        self.cursor.execute("select id, created_time from vulnerability where "
                            "vul_type = ? and target_service = ? and target_ip = ? and target_port = ?",
                            (vul['alert_group'], vul['service'], vul['ip'], vul['port']))
        ret = self.cursor.fetchone()
        create_time = t = now_time()
        if ret:
            vul_id = ret[0]
            create_time = ret[1]
            self.cursor.execute("update vulnerability set updated_time=?, details=? where id= ? ",
                                (t, vul['details'], vul_id))
            self.commit()
            update_count = 1
        else:
            self.cursor.execute("INSERT INTO vulnerability ("
                                "vul_type, severity, target_service, target_ip, target_port, "
                                "details, plugin_name, created_time, updated_time) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ",
                                (vul['alert_group'], 3, vul['service'], vul['ip'], vul['port'],
                                 vul['details'], vul['plugin_name'], t, t))
            self.commit()
            insert_count = 1
            vul_id = self.cursor.lastrowid
        return vul_id, create_time, insert_count, update_count


def create_database(name):
    db_dir = os.path.join(root_path, 'database/%s' % name)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    shutil.copyfile(os.path.join(root_path, 'ui/resource/empty_data.db'), os.path.join(db_dir, 'data.db'))


def get_db_statistics(db_name='*'):
    db_statistics = {}
    dbs = os.listdir(os.path.join(root_path, 'database')) if db_name == '*' else [db_name]
    for target in dbs:
        db_path = os.path.join(root_path, 'database/%s/data.db' % target)
        if os.path.exists(db_path):
            db_conn = sqlite3.connect(db_path)
            table_count = []
            for table in ['domain', 'ip', 'port', 'vulnerability']:
                table_count.append(db_conn.execute('select count(*) from %s' % table).fetchone()[0])
            db_statistics[target] = {
                    'domain': table_count[0],
                    'ip': table_count[1],
                    'port': table_count[2],
                    'vulnerability': table_count[3],
                    'url': 0
            }
            db_conn.close()
    return db_statistics if db_name == '*' else db_statistics[db_name]


if __name__ == '__main__':
    print(get_db_statistics('*'))
