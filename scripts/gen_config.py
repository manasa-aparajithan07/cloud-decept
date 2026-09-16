import xml.etree.ElementTree as ET

# Build the config programmatically
root = ET.Element('clickhouse')

# Logger
logger = ET.SubElement(root, 'logger')
ET.SubElement(logger, 'level').text = 'information'
ET.SubElement(logger, 'log').text = '/var/log/clickhouse-server/clickhouse-server.log'
ET.SubElement(logger, 'errorlog').text = '/var/log/clickhouse-server/clickhouse-server.err.log'
ET.SubElement(logger, 'size').text = '1000M'
ET.SubElement(logger, 'count').text = '3'

# Ports
ET.SubElement(root, 'http_port').text = '8123'
ET.SubElement(root, 'tcp_port').text = '9000'
ET.SubElement(root, 'interserver_http_port').text = '9009'

ET.SubElement(root, 'listen_host').text = '::'

ET.SubElement(root, 'max_concurrent_queries').text = '100'
ET.SubElement(root, 'max_concurrent_queries_for_user').text = '50'

ET.SubElement(root, 'mark_cache_size').text = '134217728'
ET.SubElement(root, 'uncompressed_cache_size').text = '536870912'

ET.SubElement(root, 'path').text = '/var/lib/clickhouse/'
ET.SubElement(root, 'tmp_path').text = '/var/lib/clickhouse/tmp/'
ET.SubElement(root, 'user_files_path').text = '/var/lib/clickhouse/user_files/'
ET.SubElement(root, 'format_schema_path').text = '/var/lib/clickhouse/format_schemas/'

ET.SubElement(root, 'users_config').text = 'users.xml'

user_directories = ET.SubElement(root, 'user_directories')
users_xml = ET.SubElement(user_directories, 'users_xml')
ET.SubElement(users_xml, 'path').text = 'users.xml'
local_directory = ET.SubElement(user_directories, 'local_directory')
ET.SubElement(local_directory, 'path').text = '/var/lib/clickhouse/access/'

ET.SubElement(root, 'default_database').text = 'default'
ET.SubElement(root, 'default_profile').text = 'default'

ET.SubElement(root, 'timezone').text = 'UTC'

ddl = ET.SubElement(root, 'ddl')
ET.SubElement(ddl, 'max_tasks_in_queue').text = '100'

def add_log(parent, name, table, partition_by='toYYYYMM(event_date)', **kwargs):
    log = ET.SubElement(parent, name)
    ET.SubElement(log, 'database').text = 'system'
    ET.SubElement(log, 'table').text = table
    if partition_by:
        ET.SubElement(log, 'partition_by').text = partition_by
    for k, v in kwargs.items():
        ET.SubElement(log, k).text = str(v)

# Add all logs
add_log(root, 'query_log', 'query_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', flush_on_crash='false', enable_user_query_log='true')
add_log(root, 'trace_log', 'trace_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', flush_on_crash='false', symbolize='true')
add_log(root, 'query_thread_log', 'query_thread_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', flush_on_crash='false')
add_log(root, 'query_views_log', 'query_views_log', flush_interval_milliseconds='7500')
add_log(root, 'part_log', 'part_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', flush_on_crash='false')

bg_log = ET.SubElement(root, 'background_schedule_pool_log')
ET.SubElement(bg_log, 'database').text = 'system'
ET.SubElement(bg_log, 'table').text = 'background_schedule_pool_log'
ET.SubElement(bg_log, 'partition_by').text = 'toYYYYMM(event_date)'
ET.SubElement(bg_log, 'flush_interval_milliseconds').text = '7500'
ET.SubElement(bg_log, 'max_size_rows').text = '1048576'
ET.SubElement(bg_log, 'reserved_size_rows').text = '8192'
ET.SubElement(bg_log, 'buffer_size_rows_flush_threshold').text = '524288'
ET.SubElement(bg_log, 'flush_on_crash').text = 'false'
ET.SubElement(bg_log, 'duration_threshold_milliseconds').text = '30'

add_log(root, 'text_log', 'text_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', flush_on_crash='false')
text_log = root.find('text_log')
ET.SubElement(text_log, 'level').text = 'trace'

add_log(root, 'metric_log', 'metric_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', collect_interval_milliseconds='1000', flush_on_crash='false')
add_log(root, 'error_log', 'error_log', flush_interval_milliseconds='7500', max_size_rows='1048576', reserved_size_rows='8192', buffer_size_rows_flush_threshold='524288', collect_interval_milliseconds='1000', flush_on_crash='false')

crash_log = ET.SubElement(root, 'crash_log')
ET.SubElement(crash_log, 'database').text = 'system'
ET.SubElement(crash_log, 'table').text = 'crash_log'
ET.SubElement(crash_log, 'partition_by').text = ''
ET.SubElement(crash_log, 'flush_interval_milliseconds').text = '1000'
ET.SubElement(crash_log, 'max_size_rows').text = '1024'
ET.SubElement(crash_log, 'reserved_size_rows').text = '1024'
ET.SubElement(crash_log, 'buffer_size_rows_flush_threshold').text = '512'
ET.SubElement(crash_log, 'flush_on_crash').text = 'true'

async_insert = ET.SubElement(root, 'asynchronous_insert_log')
ET.SubElement(async_insert, 'database').text = 'system'
ET.SubElement(async_insert, 'table').text = 'asynchronous_insert_log'
ET.SubElement(async_insert, 'flush_interval_milliseconds').text = '7500'
ET.SubElement(async_insert, 'max_size_rows').text = '1048576'
ET.SubElement(async_insert, 'reserved_size_rows').text = '8192'
ET.SubElement(async_insert, 'buffer_size_rows_flush_threshold').text = '524288'
ET.SubElement(async_insert, 'flush_on_crash').text = 'false'
ET.SubElement(async_insert, 'partition_by').text = 'event_date'
ET.SubElement(async_insert, 'ttl').text = 'event_date + INTERVAL 3 DAY'

add_log(root, 'backup_log', 'backup_log', partition_by='toYYYYMM(event_date)', flush_interval_milliseconds='7500')
add_log(root, 's3queue_log', 's3queue_log', partition_by='toYYYYMM(event_date)', flush_interval_milliseconds='7500')

blob_log = ET.SubElement(root, 'blob_storage_log')
ET.SubElement(blob_log, 'database').text = 'system'
ET.SubElement(blob_log, 'table').text = 'blob_storage_log'
ET.SubElement(blob_log, 'partition_by').text = 'toYYYYMM(event_date)'
ET.SubElement(blob_log, 'flush_interval_milliseconds').text = '7500'
ET.SubElement(blob_log, 'ttl').text = 'event_date + INTERVAL 30 DAY'

agg_zk = ET.SubElement(root, 'aggregated_zookeeper_log')
ET.SubElement(agg_zk, 'database').text = 'system'
ET.SubElement(agg_zk, 'table').text = 'aggregated_zookeeper_log'
ET.SubElement(agg_zk, 'partition_by').text = 'toYYYYMM(event_date)'
ET.SubElement(agg_zk, 'collect_interval_milliseconds').text = '1000'
ET.SubElement(agg_zk, 'ttl').text = 'event_date + INTERVAL 30 DAY'

zk_conn = ET.SubElement(root, 'zookeeper_connection_log')
ET.SubElement(zk_conn, 'database').text = 'system'
ET.SubElement(zk_conn, 'table').text = 'zookeeper_connection_log'
ET.SubElement(zk_conn, 'partition_by').text = 'toYYYYMM(event_date)'
ET.SubElement(zk_conn, 'ttl').text = 'event_date + INTERVAL 30 DAY'

ET.SubElement(root, 'dictionaries_config').text = '*_dictionary.*ml'
ET.SubElement(root, 'dictionaries_lazy_load').text = 'true'
ET.SubElement(root, 'wait_dictionaries_load_at_startup').text = 'true'

ET.SubElement(root, 'user_defined_executable_functions_config').text = '*_function.*ml'
ET.SubElement(root, 'user_defined_executable_function_drivers_config').text = 'user_defined_executable_function_drivers_config.d/*_driver.xml'

dist_ddl = ET.SubElement(root, 'distributed_ddl')
ET.SubElement(dist_ddl, 'path').text = '/clickhouse/task_queue/ddl'
ET.SubElement(dist_ddl, 'replicas_path').text = '/clickhouse/task_queue/replicas'

crash_reports = ET.SubElement(root, 'send_crash_reports')
ET.SubElement(crash_reports, 'enabled').text = 'true'
ET.SubElement(crash_reports, 'send_logical_errors').text = 'true'
ET.SubElement(crash_reports, 'endpoint').text = 'https://crash.clickhouse.com/'

backups = ET.SubElement(root, 'backups')
ET.SubElement(backups, 'allowed_path').text = 'backups'
ET.SubElement(backups, 'remove_backup_files_after_failure').text = 'true'

ET.SubElement(root, 'top_level_domains_lists')

ET.SubElement(root, 'google_protos_path').text = '/usr/share/clickhouse/protos/'

# query_masking_rules
masking = ET.SubElement(root, 'query_masking_rules')
rule1 = ET.SubElement(masking, 'rule')
ET.SubElement(rule1, 'name').text = 'hide encrypt/decrypt arguments'
ET.SubElement(rule1, 'regexp').text = r"((?:aes_)?(?:encrypt|decrypt)(?:_mysql)?)\s*\(\s*(?:'(?:\'|.)+'|.*?)\s*\)"
ET.SubElement(rule1, 'replace').text = r'\1(???)'
rule2 = ET.SubElement(masking, 'rule')
ET.SubElement(rule2, 'name').text = 'hide sensitive HTTP query-string parameters'
ET.SubElement(rule2, 'regexp').text = r'([?&][^&=]*(?:secret|password|passwd|token|credential|signature|key)[^&=]*=)[^&\s]*'
ET.SubElement(rule2, 'replace').text = r'\1[HIDDEN]'

http_handlers = ET.SubElement(root, 'http_handlers')
ET.SubElement(http_handlers, 'defaults')

ET.SubElement(root, 'builtin_dictionaries_reload_interval').text = '3600'
ET.SubElement(root, 'max_session_timeout').text = '3600'
ET.SubElement(root, 'default_session_timeout').text = '60'

# Write
tree = ET.ElementTree(root)
ET.indent(tree, space='    ')
tree.write('C:/Users/raviv/cloud-decept/configs/clickhouse/config.xml', encoding='utf-8', xml_declaration=True)

print('Written successfully')