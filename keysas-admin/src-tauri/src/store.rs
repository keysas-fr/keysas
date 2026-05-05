//! Handle the application data storage
//! The application data is stored via sqlite in the file ".keysas.dat"
//!
//! Data is stored in three tables:
//!
//! SSH table (key: TEXT, value: TEXT)
//!     - name is either "public" or "private"
//!     - path is the path to the SSH key
//! Station table (name: TEXT, ip: TEXT)
//! CA table (key: TEXT, value: TEXT)

use std::{path::Path, sync::Mutex};

use anyhow::anyhow;
use serde::Serialize;
use sqlite::Connection;

use keysas_lib::certificate_field::CertificateFields;

static STORE_HANDLE: Mutex<Option<Connection>> = Mutex::new(None);

const CREATE_QUERY: &str = "
    CREATE TABLE IF NOT EXISTS ssh_table (name TEXT PRIMARY KEY, path TEXT);
    CREATE TABLE IF NOT EXISTS station_table (name TEXT PRIMARY KEY, ip TEXT);
    CREATE TABLE IF NOT EXISTS ca_table (name TEXT PRIMARY KEY, directory TEXT, org_name TEXT, org_unit TEXT, country TEXT, validity TEXT);
";

const GET_PUBLIC_QUERY: &str = "SELECT * FROM ssh_table WHERE name='public';";
const GET_PRIVATE_QUERY: &str = "SELECT * FROM ssh_table WHERE name='private';";

/// Structure representing a station in the store
#[derive(Debug, Serialize)]
pub struct Station {
    name: String,
    ip: String,
}

/// Initialize the application store
/// Takes the path to the store
pub fn init_store(path: &str) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        }
        Ok(mut hdl) => {
            match hdl.as_ref() {
                Some(_) => return Ok(()),
                None => {
                    match sqlite::open(path) {
                        Ok(c) => {
                            // Initialize the store and return the connection
                            match c.execute(CREATE_QUERY) {
                                Ok(_) => {
                                    log::debug!("Store initialized");
                                    *hdl = Some(c);
                                }
                                Err(e) => {
                                    return Err(anyhow!("Failed to initialize database: {e}"));
                                }
                            }
                        }
                        Err(e) => {
                            return Err(anyhow!("Failed to connect to the database: {e}"));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Return a tuple containing (path to public ssh key, path to private ssh key)
pub fn get_ssh() -> Result<(String, String), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let mut public = String::new();
                let mut private = String::new();

                connection.iterate(GET_PUBLIC_QUERY, |pairs| {
                    for &(key, value) in pairs.iter() {
                        if key == "path"
                            && let Some(p) = value
                        {
                            public.push_str(p)
                        }
                    }
                    true
                })?;
                connection.iterate(GET_PRIVATE_QUERY, |pairs| {
                    for &(key, value) in pairs.iter() {
                        if key == "path"
                            && let Some(p) = value
                        {
                            private.push_str(p)
                        }
                    }
                    true
                })?;
                if (public.chars().count() > 0) && (private.chars().count() > 0) {
                    log::debug!("Found: {public}, {private}");
                    Ok((public, private))
                } else {
                    Err(anyhow!("get_ssh: Failed to find station in database"))
                }
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Save the paths to the public and private SSH keys
/// The function first checks that the path are valid files
pub fn set_ssh(public: &str, private: &str) -> Result<(), anyhow::Error> {
    if !Path::new(public.trim()).is_file() || !Path::new(private.trim()).is_file() {
        return Err(anyhow!("Invalid paths"));
    }

    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let mut query = connection.prepare(
                    "REPLACE INTO ssh_table (name, path) VALUES ('public', ?), ('private', ?);",
                )?;

                query.bind((1, public))?;
                query.bind((2, private))?;
                query.next()?;
                Ok(())
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Save the paths to the public and private SSH keys
/// The function first checks that the path are valid files
pub fn set_station(name: &str, ip: &str) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let mut query =
                    connection.prepare("REPLACE INTO station_table (name, ip) VALUES (?, ?);")?;
                query.bind((1, name))?;
                query.bind((2, ip))?;
                //log::debug!("Query: {}", query);
                query.next()?;
                Ok(())
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Delete a Keysas station
pub fn delete_station(name: &str) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let mut query = connection.prepare("DELETE FROM station_table WHERE name = ?;")?;
                query.bind((1, name))?;
                //log::debug!("Query: {}", query);
                query.next()?;
                Ok(())
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Drop the current PKI
pub async fn drop_pki() -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let query = "DROP TABLE ca_table; CREATE TABLE IF NOT EXISTS ca_table (name TEXT PRIMARY KEY, directory TEXT, org_name TEXT, org_unit TEXT, country TEXT, validity TEXT);".to_string();
                log::debug!("Query: {query}");
                connection.execute(query)?;
                Ok(())
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Get the station IP address by name
/// Returns an error if the station does not exist or in case of trouble accessing
/// the database
pub fn get_station_ip_by_name(name: &str) -> Result<String, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let query = connection.prepare("SELECT * FROM station_table WHERE name = ?;")?;
                let mut result = String::new();
                for row in query.into_iter().bind((1, name))? {
                    let row = row?;
                    result = row.read::<&str, _>("ip").to_string();
                }
                if result.chars().count() > 0 {
                    log::debug!("Found: {result}");
                    Ok(result)
                } else {
                    Err(anyhow!("Failed to find station in database"))
                }
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Get the list of station registered in the admin backend
/// Returns an error in case of trouble accessing the database
pub fn get_station_list() -> Result<Vec<Station>, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let query = "SELECT * FROM station_table;".to_string();
                let mut result = Vec::new();
                connection.iterate(query, |pairs| {
                    let mut st = Station {
                        name: String::new(),
                        ip: String::new(),
                    };
                    for &(key, value) in pairs.iter() {
                        match key {
                            "name" => {
                                if let Some(n) = value {
                                    st.name.push_str(n)
                                }
                            }
                            "ip" => {
                                if let Some(i) = value {
                                    st.ip.push_str(i)
                                }
                            }
                            _ => (),
                        }
                    }
                    result.push(st);
                    true
                })?;
                log::debug!("Found: {result:?}");
                Ok(result)
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

/// Save the PKI configuration infos
/// Returns Ok or an Error
pub fn set_pki_config(pki_dir: &str, infos: &CertificateFields) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let mut query = connection.prepare("REPLACE INTO ca_table (name, directory, org_name, org_unit, country, validity) \
                                        VALUES (?,?,?,?,?,?);")?;
                query.bind((1, infos.org_name.as_deref().unwrap_or("")))?;
                query.bind((2, pki_dir))?;
                query.bind((3, infos.org_name.as_deref().unwrap_or("")))?;
                query.bind((4, infos.org_unit.as_deref().unwrap_or("")))?;
                query.bind((5, infos.country.as_deref().unwrap_or("")))?;
                query.bind((6, infos.validity.unwrap_or(0) as i64))?;
                //log::debug!("Query: {}", query);
                query.next()?;
                Ok(())
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

pub fn get_pki_dir() -> Result<String, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let query = "SELECT * FROM ca_table;".to_string();
                let mut result = String::new();
                connection.iterate(query, |pairs| {
                    for &(key, value) in pairs.iter() {
                        log::debug!("{key:?}:{value:?}");
                        if key == "directory"
                            && let Some(dir) = value
                        {
                            result.push_str(dir)
                        }
                    }
                    true
                })?;
                log::debug!("Found: {result:?}");
                Ok(result)
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}

pub fn get_pki_info() -> Result<CertificateFields, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => Err(anyhow!("Failed to get database lock: {e}")),
        Ok(hdl) => match hdl.as_ref() {
            Some(connection) => {
                let query = "SELECT * FROM ca_table;".to_string();
                log::debug!("Query is: {query}");
                let mut result = CertificateFields {
                    org_name: None,
                    org_unit: None,
                    country: None,
                    common_name: None,
                    validity: None,
                };
                connection.iterate(query, |pairs| {
                    for &(param, value) in pairs.iter() {
                        match param {
                            "org_name" => result.org_name = Some(value.unwrap().to_string()),
                            "org_unit" => result.org_unit = Some(value.unwrap().to_string()),
                            "country" => result.country = Some(value.unwrap().to_string()),
                            "validity" => {
                                let num = match value.unwrap().parse::<u32>() {
                                    Ok(n) => n,
                                    Err(_) => {
                                        return true;
                                    }
                                };
                                result.validity = Some(num);
                            }
                            _ => (),
                        }
                    }
                    true
                })?;
                log::debug!("Found: {result:?}");
                Ok(result)
            }
            None => Err(anyhow!("Store is not initialized")),
        },
    }
}
