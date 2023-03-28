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

use std::{sync::Mutex, path::Path};

use anyhow::anyhow;
use sqlite::Connection;
use serde::Serialize;

use keysas_lib::pki::*;

static STORE_HANDLE: Mutex<Option<Connection>> = Mutex::new(None);

const CREATE_QUERY: &str = "
    CREATE TABLE IF NOT EXISTS ssh_table (name TEXT, path TEXT);
    CREATE TABLE IF NOT EXISTS station_table (name TEXT, ip TEXT);
    CREATE TABLE IF NOT EXISTS ca_table (param TEXT, value TEXT);
";

const GET_PUBLIC_QUERY: &str = "SELECT * FROM ssh_table WHERE name='public';";
const GET_PRIVATE_QUERY: &str = "SELECT * FROM ssh_table WHERE name='private';";

/// Structure representing a station in the store
#[derive(Debug, Serialize)]
pub struct Station {
    name: String,
    ip: String
}

/// Initialize the application store
/// Takes the path to the store
pub fn init_store(path: &str) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(mut hdl) => {
            match hdl.as_ref() {
                Some(_) => return Ok(()),
                None => {
                    match sqlite::open(path) {
                        Ok(c) => {
                            // Initialize the store and return the connection
                            match c.execute(CREATE_QUERY) {
                                Ok(_) => {
                                    *hdl = Some(c);
                                },
                                Err(e) => {
                                    return Err(anyhow!("Failed to initialize database: {e}"))
                                }
                            }
                        },
                        Err(e) => {
                            return Err(anyhow!("Failed to connect to the database: {e}"));
                        }
                    }
                }
            }
        }
    }
    return Ok(())
}

/// Return a tuple containing (path to public ssh key, path to private ssh key)
pub fn get_ssh() -> Result<(String, String), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let mut public = String::new();
                    let mut private = String::new();
            
                    connection.iterate(GET_PUBLIC_QUERY, |pairs| {
                        for &(key, value) in pairs.iter() {
                            match key {
                                "path" => {
                                    match value {
                                        Some(p) => public.push_str(p),
                                        None => ()
                                    }
                                },
                                _ => ()
                            }
                        }
                        true
                    })?;
                    connection.iterate(GET_PRIVATE_QUERY, |pairs| {
                        for &(key, value) in pairs.iter() {
                            match key {
                                "path" => {
                                    match value {
                                        Some(p) => private.push_str(p),
                                        None => ()
                                    }
                                },
                                _ => ()
                            }
                        }
                        true
                    })?;
                    if (public.chars().count() > 0) 
                            && (private.chars().count() > 0) {
                        log::debug!("Found: {}, {}", public, private);
                        return Ok((public, private));
                    } else {
                        return Err(anyhow!("Failed to find station in database"));
                    }
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}

/// Save the paths to the public and private SSH keys
/// The function first checks that the path are valid files
pub fn set_ssh(public: &String, private: &String) -> Result<(), anyhow::Error> {
    if !Path::new(public.trim()).is_file() ||
        !Path::new(private.trim()).is_file() {
        return Err(anyhow!("Invalid paths"));
    }

    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let query = format!("REPLACE INTO ssh_table (name, path) VALUES ('public', '{}'), ('private', '{}');",
                        public, private);
                    connection.execute(query)?;
                    return Ok(());
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}

/// Save the paths to the public and private SSH keys
/// The function first checks that the path are valid files
pub fn set_station(name: &String, ip: &String) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let query = format!("REPLACE INTO station_table (name, ip) VALUES ('{}', '{}');",
                        name, ip);
                    log::debug!("Query: {}", query);
                    connection.execute(query)?;
                    return Ok(());
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}

/// Get the station IP address by name
/// Returns an error if the station does not exist or in case of trouble accessing
/// the database
pub fn get_station_ip_by_name(name: &String) -> Result<String, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let query = format!("SELECT * FROM station_table WHERE name = '{}';",
                        name);
                    let mut result = String::new();
                    log::debug!("Query: {}", query);
                    connection.iterate(query, |pairs| {
                        for &(key, value) in pairs.iter() {
                            match key {
                                "ip" => {
                                    match value {
                                        Some(ip) => {
                                            result.push_str(ip);
                                        },
                                        None => ()
                                    }
                                }
                                _ => ()
                            }
                        }
                        true
                    })?;
                    if result.chars().count() > 0 {
                        log::debug!("Found: {}", result);
                        return Ok(result);
                    } else {
                        return Err(anyhow!("Failed to find station in database"));
                    }
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}

/// Get the list of station registered in the admin backend
/// Returns an error in case of trouble accessing the database
pub fn get_station_list() -> Result<Vec<Station>, anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let query = format!("SELECT * FROM station_table;");
                    let mut result = Vec::new();
                    connection.iterate(query, |pairs| {
                        let mut st = Station {
                            name: String::new(),
                            ip: String::new()
                        };
                        for &(key, value) in pairs.iter() {
                            match key {
                                "name" => {
                                    match value {
                                        Some(n) => st.name.push_str(n),
                                        None => ()
                                    }
                                },
                                "ip" => {
                                    match value {
                                        Some(i) => st.ip.push_str(i),
                                        None => ()
                                    }
                                }
                                _ => ()
                            }
                        }
                        result.push(st);
                        true
                    })?;
                    log::debug!("Found: {:?}", result);
                    return Ok(result);
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}

/// Save the PKI configuration infos
/// Returns Ok or an Error
pub fn set_pki_config(pki_dir: &String, infos: &CertificateFields) -> Result<(), anyhow::Error> {
    match STORE_HANDLE.lock() {
        Err(e) => {
            return Err(anyhow!("Failed to get database lock: {e}"));
        },
        Ok(hdl) => {
            match hdl.as_ref() {
                Some(connection) => {
                    let query = format!("REPLACE INTO ca_table (param, value) \
                                        VALUES ('directory', '{}'), ('org_name', '{}'), \
                                        ('org_unit', '{}'), ('country', '{}'), \
                                        ('validity', '{}');",
                        pki_dir, &infos.org_name, &infos.org_unit,
                        &infos.country, &infos.validity);
                    log::debug!("Query: {}", query);
                    connection.execute(query)?;
                    return Ok(());
                },
                None => {
                    return Err(anyhow!("Store is not initialized"));
                }
            }
        }
    }
}