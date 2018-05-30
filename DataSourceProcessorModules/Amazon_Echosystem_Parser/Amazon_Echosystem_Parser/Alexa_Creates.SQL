drop table alexa_databases;
create table alexa_databases
(File_name text, artifact_name text, artifact_description text,
 sql_to_run text);

insert into alexa_databases values
 ('map_data_storage_v2.db','TSK_ALEXA_MAP_DATA_ACCOUNTS','Alexa Map Data Storage Accounts',
  'select display_name, directed_id, account_data_key, account_data_value
  from accounts a, account_data b
 where a.directed_id = b.account_data_directed_id;'); 

insert into alexa_databases values
 ('map_data_storage_v2.db','TSK_ALEXA_MAP_DATA_DEVICES','Alexa Map Data Storage Devices',
  'select device_data_namespace, device_data_key, device_data_value
  from device_data;');

insert into alexa_databases values
 ('arn_aws_remote-config_us-west-2_412793207129_appConfig_ayuw5hfh_ConfigurationCache.db','TSK_ALEXA_REMOTE_CONFIG','Alexa Remote Configuration',
  "select strftime('%Y-%m-%d %H:%M:%S', timestamp / 1000, 'unixepoch') timestamp,
       b.key, b.value, b.type, b.atom, b.id, b.parent, b.fullkey, b.path
 from configuration a, json_tree(a.json) b       
 order by b.id, b.parent;");
 
insert into alexa_databases values
 ('Index','TSK_ALEXA_INDEX_CACHES','Alexa Index Caches',
  "select cache_id, datetime((substr(update_time,1,11)-11644473600),'UNIXEPOCH') update_time,
          cache_size
     from caches;"); 

insert into alexa_databases values
 ('Index','TSK_ALEXA_INDEX_ENTRIES','Alexa Index Entries',
  'select cache_id, url, flags, response_id, response_size
     from entries;');
     
insert into alexa_databases values
 ('Index','TSK_ALEXA_INDEX_GROUPS','Alexa Index Groups',
  "select origin, manifest_url,
       datetime((substr(creation_time,1,11)-11644473600),'UNIXEPOCH') creation_time,
       datetime((substr(last_access_time,1,11)-11644473600),'UNIXEPOCH') last_access_time,
       datetime((substr(last_full_update_check_time,1,11)-11644473600),'UNIXEPOCH') last_full_update_check_time,
       datetime((substr(first_evictable_error_time,1,11)-11644473600),'UNIXEPOCH') first_evictable_error_time
 from groups;");

insert into alexa_databases values
 ('QuotaManager','TSK_ALEXA_QUOTA_MANAGER','Alexa Quota Manager Origin Info',
  "select origin, used_count, 
       datetime((substr(last_access_time,1,11)-11644473600),'UNIXEPOCH') last_access_time,
       datetime((substr(last_modified_time,1,11)-11644473600),'UNIXEPOCH') last_modified_time
 from OriginInfoTable;");

insert into alexa_databases values
 ('datastore.db','TSK_ALEXA_DATASTORE','Alexa Data Store',
  "select a.key, b.id, b.parent, b.key, b.value from dataitem a, json_tree(a.value) b
 order by a.key, b.id, b.parent;");

insert into alexa_databases values
 ('Cookies','TSK_ALEXA_COOKIES','Alexa Cookies',
  "select datetime((substr(creation_utc,1,11)-11644473600),'UNIXEPOCH') creation_utc,
       host_key,name, value, path, 
       datetime((substr(expires_utc,1,11)-11644473600),'UNIXEPOCH') expires_utc,
       datetime((substr(last_access_utc,1,11)-11644473600),'UNIXEPOCH') last_access_utc
 from cookies;");

insert into alexa_databases values
 ('iot.1.db','TSK_KASA_IOT_ACCOUNTS','Kasa IOT Accounts',
  "select strftime('%Y-%m-%d %H:%M:%S', createdOn / 1000, 'unixepoch') createdOn, 
       email, firstName, LastName, id, password, Token,
       strftime('%Y-%m-%d %H:%M:%S', updatedOn / 1000, 'unixepoch') updatedOn
 from accounts;");

insert into alexa_databases values
 ('iot.1.db','TSK_KASA_IOT_DEVICES','Kasa IOT Devices',
  "select strftime('%Y-%m-%d %H:%M:%S', createdOn / 1000, 'unixepoch') createdOn, 
       deviceAlias, DeviceCategory, deviceModel, deviceName, deviceType, 
       ipAddress, password,
       strftime('%Y-%m-%d %H:%M:%S', updatedOn / 1000, 'unixepoch') updatedOn
 from devices;");

insert into alexa_databases values
 ('locations_vs','TSK_ALEXA_LOCATIONS_V2','Alexa Locations',
  "select strftime('%Y-%m-%d %H:%M:%S', createdOn / 1000, 'unixepoch') createdOn, 
       longitude, 
       latitude,
       timezoneId,
       strftime('%Y-%m-%d %H:%M:%S', updatedOn / 1000, 'unixepoch') updatedOn
 from locations_v2;");
 
 
