from lib.common import is_port_num


"""
 This class helps to generate complex SQL Query that needs join different tables
"""


class SQLGenerator(object):
    def __init__(self, table_name, keyword):
        self.table_name = table_name
        self.keyword = keyword
        self.count_sql = ''
        self.fetch_sql = ''
        self.delete_sql = ''
        self.get_count_sql()
        self.get_fetch_sql()
        self.get_delete_sql()

    def get_count_sql(self):
        sql_domain_count = """select count(*) from (SELECT domain.name as ips from domain 
    JOIN domain_ips on domain.id = domain_ips.domain_id join ip on ip.id=domain_ips.ip_id 
    where domain.name like '%{}%'
    GROUP by domain.name)
    """
        sql_ip_count = """
    SELECT count(*) from ip
    where ip.ip_addr like '%{}%'
    """
        sql_vul_count = """select count(*) from vulnerability where 
        vul_type like '%{}%' or target_ip like '%{}%' or details like '%{}%'
    """
        sql_port_count_prefix = """
    SELECT count(*) from (
        SELECT ip.ip_addr, port.port_no, 
               port.service_name, port.service_version, port.is_http, group_concat(domain.name) as domains from port
        JOIN ip ON port.ip_id=ip.id 
        left JOIN domain_ips on ip.id = domain_ips.ip_id
        left JOIN domain 
        on domain.id=domain_ips.domain_id
        group by ip.ip_addr, port.port_no
    """

        if self.table_name == 'domain':
            sql = sql_domain_count.format(self.keyword)
        elif self.table_name == 'ip':
            sql = sql_ip_count.format(self.keyword)
        elif self.table_name == 'vulnerability':
            sql = sql_vul_count.format(self.keyword, self.keyword, self.keyword)
        else:
            if not self.keyword:
                sql = sql_port_count_prefix + ')'
            elif is_port_num(self.keyword):
                condition = " having port.port_no=%s " % self.keyword
                sql = sql_port_count_prefix + condition + ')'
            elif self.keyword.lower().find('domain=') >= 0:
                domain = self.keyword.split('=')[1].strip()
                sql = sql_port_count_prefix + """ having domains like '%{}%') """.format(domain)
            else:
                condition = " having (service_name like '%{}%' or service_version like '%{}%')".format(
                    self.keyword, self.keyword)
                sql = sql_port_count_prefix + condition + ')'
        self.count_sql = sql

    def get_fetch_sql(self):
        sql_domain_fetch_all = """
        SELECT domain.id, domain.name, GROUP_CONCAT(ip.ip_addr) as ips, domain.created_time, domain.updated_time 
        from domain
        JOIN domain_ips on domain.id = domain_ips.domain_id
        join ip on ip.id=domain_ips.ip_id
        where domain.name like '%{}%' GROUP by domain.name order by domain.id asc"""

        sql_ip_fetch_all = """
        SELECT ip.id, ip.ip_addr, group_concat(domain.name) as domains, ip.created_time, ip.updated_time from ip
        left JOIN domain_ips on ip.id = domain_ips.ip_id
        left JOIN domain on domain.id = domain_ips.domain_id
        where ip.ip_addr like '%{}%'
        GROUP BY ip.ip_addr order by ip.id asc"""

        sql_vul_fetch_all = """
        select * from vulnerability where 
        vul_type like '%{}%' or target_ip like '%{}%' or details like '%{}%'"""

        sql_port_fetch_all_prefix = """
        SELECT port.id, ip.ip_addr, port.port_no, 
               port.service_name, port.service_version, port.is_http, group_concat(domain.name) as domains from port
        JOIN ip ON port.ip_id=ip.id 
        left JOIN domain_ips on ip.id = domain_ips.ip_id
        left JOIN domain 
        on domain.id=domain_ips.domain_id
        group by ip.ip_addr, port.port_no
        {}
        order by port.id asc
        """

        sql = ''
        if self.table_name == 'domain':
            sql = sql_domain_fetch_all.format(self.keyword)
        elif self.table_name == 'ip':
            sql = sql_ip_fetch_all.format(self.keyword)
        elif self.table_name == 'vulnerability':
            sql = sql_vul_fetch_all.format(self.keyword, self.keyword, self.keyword)
        elif self.table_name == 'port':
            if not self.keyword:
                sql = sql_port_fetch_all_prefix.format('')
            elif is_port_num(self.keyword):
                condition = " having port.port_no=%s " % self.keyword
                sql = sql_port_fetch_all_prefix.format(condition)
            elif self.keyword.lower().find('domain=') >= 0:
                keyword = self.keyword.split('=')[1].strip()
                condition = """ having domains like '%{}%' """.format(keyword)
                sql = sql_port_fetch_all_prefix.format(condition)
            else:
                condition = " having (service_name like '%{}%' or service_version like '%{}%')".format(
                    self.keyword, self.keyword)
                sql = sql_port_fetch_all_prefix.format(condition)
        self.fetch_sql = sql

    def get_delete_sql(self):
        sql_domain_delete_all = """
        delete from domain where id in (
            SELECT domain.id 
            from domain
            JOIN domain_ips on domain.id = domain_ips.domain_id
            join ip on ip.id=domain_ips.ip_id
            where domain.name like '%{}%' GROUP by domain.name order by domain.id asc
        )"""

        sql_ip_delete_all = """
        delete from ip where id in (
            SELECT ip.id from ip
            left JOIN domain_ips on ip.id = domain_ips.ip_id
            left JOIN domain on domain.id = domain_ips.domain_id
            where ip.ip_addr like '%{}%'
            GROUP BY ip.ip_addr order by ip.id asc
        )"""

        sql_vul_delete_all = """
        delete from vulnerability where 
        vul_type like '%{}%' or target_ip like '%{}%' or details like '%{}%'"""

        sql_port_delete_all_prefix = """
        delete from port where id in (
            SELECT port.id from port
            JOIN ip ON port.ip_id=ip.id 
            left JOIN domain_ips on ip.id = domain_ips.ip_id
            left JOIN domain 
            on domain.id=domain_ips.domain_id
            group by ip.ip_addr, port.port_no
            {}
            order by port.id asc
        )
        """

        sql = ''
        if self.table_name == 'domain':
            sql = sql_domain_delete_all.format(self.keyword)
        elif self.table_name == 'ip':
            sql = sql_ip_delete_all.format(self.keyword)
        elif self.table_name == 'vulnerability':
            sql = sql_vul_delete_all.format(self.keyword, self.keyword, self.keyword)
        elif self.table_name == 'port':
            if not self.keyword:
                sql = sql_port_delete_all_prefix.format('')
            elif is_port_num(self.keyword):
                condition = " having port.port_no=%s " % self.keyword
                sql = sql_port_delete_all_prefix.format(condition)
            elif self.keyword.lower().find('domain=') >= 0:
                keyword = self.keyword.split('=')[1].strip()
                condition = """ having domains like '%{}%' """.format(keyword)
                sql = sql_port_delete_all_prefix.format(condition)
            else:
                condition = " having (service_name like '%{}%' or service_version like '%{}%')".format(
                    self.keyword, self.keyword)
                sql = sql_port_delete_all_prefix.format(condition)
        self.delete_sql = sql
