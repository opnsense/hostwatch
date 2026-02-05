use anyhow::{Result};
use rusqlite::Connection;
use tracing::{debug, info, error};
use csv;
use serde::{Deserialize, Serialize};

/**
 * Host info record, used to update and return host information
 */
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostInfo {
    /* input */
    pub interface_name: Option<String>,
    pub ip_address: Option<String>,
    pub protocol: Option<String>,
    pub ether_address: Option<String>,
    pub real_ether_address: Option<String>, /* for arp the announcement may differ */
    /* result data */
    pub id: Option<i32>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub prev_ether_address: Option<String>,
    pub prev_real_ether_address: Option<String>,
    pub prev_last_seen: Option<String>,
    pub was_inserted: Option<i32>,
    pub sec_since_last_update: Option<i32>
}

impl HostInfo {
    pub fn new() -> Self {
        Self {
            interface_name: None,
            ip_address: None,
            protocol: None,
            ether_address: None,
            real_ether_address: None,
            id: None,
            first_seen: None,
            last_seen: None,
            prev_ether_address: None,
            prev_real_ether_address: None,
            prev_last_seen: None,
            was_inserted: None,
            sec_since_last_update: None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OUI {
    #[serde(rename = "Assignment")]
    pub assignment: String,
    #[serde(rename = "Organization Name")]
    pub organization_name: String,
    #[serde(rename = "Organization Address")]
    pub organization_address: String
}

pub struct Database {
    conn: Connection,
    transaction_counter: i32
}

impl Database {
    pub fn new(database: String, oui_path: String) -> Result<Self> {
        let conn = match Connection::open(database) {
            Ok(conn) => conn,
            Err(error) => {
                error!("Unable to connect to database : {error:?}");
                println!("Unable to connect to database : {error:?}");
                std::process::exit(1);
            }
        };
        if let Err(error) = conn.execute_batch("
            pragma journal_mode = WAL;
            pragma journal_size_limit = 134217728; -- 128MB
            pragma synchronous = NORMAL;
            pragma temp_store = MEMORY;
        ") {
            error!("Failed to apply PRAGMAs: {error:?}");
        }
        let mut db = Self { conn, transaction_counter: 0 };
        db.initialize_tables()?;
        match db.import_oui_csv(oui_path.as_str()) {
            Ok(_) => {}
            Err(error) => {
                error!("Skip import OUI : {error:?}");
            }
        }
        Ok(db)
    }

    fn initialize_tables(&self) -> Result<()> {
        let init_sql = ["
            vacuum",
            "
            create table if not exists hosts (
                id integer primary key autoincrement,
                interface_name text,
                ip_address text,
                protocol text,
                ether_address text,
                real_ether_address text,
                first_seen timestamp default current_timestamp not null,
                last_seen timestamp default current_timestamp not null,
                prev_ether_address text,
                prev_real_ether_address text,
                prev_last_seen timestamp,
                update_interval_sec integer,
                unique(protocol, interface_name, ip_address)
            )","
            create table if not exists oui (
                assignment TEXT PRIMARY KEY,
                organization_name  TEXT,
                organization_address TEXT
            )","
            create index if not exists hosts_idx_oui
                   on hosts (upper(replace(substr(ether_address,0,9),':','')))
            ","
            create index if not exists hosts_idx_ether_address on hosts (ether_address)
            ","
            drop view if exists v_hosts
            ","
            create view v_hosts as
            select *
            from hosts
            left join oui on oui.assignment = upper(replace(substr(hosts.ether_address,0,9),':',''));
         "];

        for sql in init_sql.iter() {
            self.conn.execute(sql, [])?;
            debug!("{:?}", sql.trim());
        }
        info!("Database tables initialized");
        Ok(())
    }

    pub fn update_host(&mut self, host_info: &HostInfo, update_interval: Option<u32>) -> Result<Option<HostInfo>> {
        /* prevent updates when seen quite recent [update_interval] and nothing relevant has changed */
        let result: rusqlite::Result<(Option<String>, Option<String>, Option<u32>)> = self.conn.query_row(
            "
            select  ether_address,
                    real_ether_address,
                    cast(strftime('%s', current_timestamp) as integer) - cast(strftime('%s', last_seen) as integer) ts
            from    hosts
            where protocol = ?1 and interface_name = ?2 and ip_address = ?3",
            rusqlite::params![
                host_info.protocol,
                host_info.interface_name,
                host_info.ip_address
            ], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                ))
            },);
        if result.is_ok() {
            let (ether_address, real_ether_address, ts) = result?;
            if ether_address == host_info.ether_address &&
                real_ether_address == host_info.real_ether_address &&
                ts < update_interval
            {
                return Ok(None);
            }
        }

        let sql = "
            insert into hosts (protocol, interface_name, ether_address, real_ether_address, ip_address, update_interval_sec)
            values (?1, ?2, ?3, ?4, ?5, 0)
            on conflict do update set last_seen = current_timestamp,
                ether_address = excluded.ether_address,
                real_ether_address = excluded.real_ether_address,
                prev_ether_address = case
                        when ether_address = excluded.ether_address
                        then prev_ether_address
                        else ether_address
                end,
                prev_real_ether_address = case
                        when real_ether_address = excluded.real_ether_address
                        then prev_real_ether_address
                        else real_ether_address
                end,
                prev_last_seen = case
                        when ether_address = excluded.ether_address and real_ether_address = excluded.real_ether_address
                        then prev_last_seen
                        else last_seen
                end,
                -- only set update_interval_sec to a value other than -1 when  some relevant update has been captured
                -- this works both as a modification indicator and a counter (time) between now and last update (last_seen)
                update_interval_sec = case
                        when ether_address = excluded.ether_address and real_ether_address = excluded.real_ether_address
                        then -1
                        else cast(strftime('%s', current_timestamp) as integer) - cast(strftime('%s', last_seen) as integer)
                end
            returning
                id, first_seen, last_seen, prev_ether_address, prev_real_ether_address,
                prev_last_seen, update_interval_sec,
                (case when last_seen = first_seen then 1 else 0 END) as inserted

        ";
        debug!("{:?} {:?}", sql.trim(), host_info);
        self.transaction_counter += 1;
        if self.transaction_counter > 10000 {
            /* force a vacuum every X updates */
            self.conn.execute("vacuum", [])?;
            self.transaction_counter = 0;
        }
        match self.conn.query_row(
            sql,
            rusqlite::params![
                host_info.protocol,
                host_info.interface_name,
                host_info.ether_address,
                host_info.real_ether_address,
                host_info.ip_address
            ],
            |row| Ok({
                let mut result = HostInfo::new();
                result.interface_name = host_info.interface_name.clone();
                result.ip_address = host_info.ip_address.clone();
                result.protocol = host_info.protocol.clone();
                result.ether_address = host_info.ether_address.clone();
                result.real_ether_address = host_info.real_ether_address.clone();
                result.id = row.get(0)?;
                result.first_seen = row.get(1)?;
                result.last_seen = row.get(2)?;
                result.prev_ether_address = row.get(3)?;
                result.prev_real_ether_address = row.get(4)?;
                result.prev_last_seen = row.get(5)?;
                result.sec_since_last_update = row.get(6)?;
                result.was_inserted = row.get(7)?;
                result
            })
        ) {
            Ok(result) => Ok(Some(result)),
            Err(e) => {
                error!("Failed to update host info: {}", e);
                Ok(None)
            }
        }
    }

    pub fn import_oui_csv(&mut self, oui_path: &str) -> Result<()> {
        let sql = "
            insert into oui (assignment,organization_name,organization_address)
            values (?,?,?)
            on conflict do update set organization_name = excluded.organization_name,
                                      organization_address = excluded.organization_address
        ";

        let mut rdr = csv::Reader::from_path(oui_path)?;
        for (i, result) in rdr.deserialize::<OUI>().enumerate() {
            match result {
                Ok(oui) => {
                    self.conn.execute(
                        sql,
                        rusqlite::params![
                            oui.assignment.trim(),
                            oui.organization_name.trim(),
                            oui.organization_address.trim()
                        ]
                    )?;
                }
                Err(e) => eprintln!("row {} error: {}", i + 2, e), // +2 to account for header and 0-index
            }
        }
        info!("Database table oui updated");
        Ok(())
    }
}
