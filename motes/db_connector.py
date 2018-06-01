import pymysql
import yaml


class Mycli:
    def __init__(self, config=None):
        self.config = config
        self.con = self.connect()

    def connect(self):
        return pymysql.connect(**self.config)

    def query_info(self, query_condition, table_name, attributes):
        attri_str = ', '.join(attributes)
        key, value = query_condition.popitem()
        query_str = (f"{key}='{value}'")
        sql_ori = (f"SELECT {attri_str} from {table_name} where {query_str}")
        cursor = self.con.cursor()
        cursor.execute(sql_ori)
        row = cursor.fetchall()
        cursor.close()
        return row

    def disconnect(self):
        self.con.close()

if __name__ == '__main__':
    with open('config.yml') as f:
        config = yaml.load(f)
    database_config = config.get('database').get('mysql')
    cli = Mycli(config=database_config)
    row = cli.query_info(
        query_condition={
            'DevAddr': '55667788',
        },
        table_name='DeviceInfo',
        attributes=['AppSKey', 'NwkSKey']
    )[0]
    print(row)

