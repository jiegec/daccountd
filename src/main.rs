#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("../target/bindings.rs");

use anyhow::anyhow;
use bytes::BytesMut;
use clap::{App, Arg};
use etcd_client::{Client, Compare, GetOptions, Txn, TxnOp, TxnOpResponse};
use gethostname::gethostname;
use lber::{structure::StructureTag, Consumer, ConsumerState, Input, Move, Parser};
use ldap3_server::{
    proto::{LdapBindResponse, LdapMsg, LdapResult, LdapSubstringFilter},
    DisconnectionNotice, LdapFilter, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
    LdapSearchScope,
};
use log::*;
use serde_derive::Deserialize;
use std::{collections::HashMap, convert::TryFrom, fs::File, io::Read, unimplemented};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::yield_now,
};

#[derive(Deserialize)]
struct Config {
    host: Vec<Host>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Host {
    name: String,
    data: Option<String>,
    log: Option<String>,
    ldap: Option<String>,
    advertise_client: String,
    listen_client: String,
    advertise_peer: String,
    listen_peer: String,
}

pub fn go_string(s: &str) -> GoString {
    GoString {
        p: s.as_bytes().as_ptr() as *const i8,
        n: s.len() as isize,
    }
}

pub fn match_filter(filter: &LdapFilter, attrs: &HashMap<String, Vec<String>>) -> bool {
    use LdapFilter::*;
    match filter {
        And(f) => f.iter().all(|f| match_filter(f, attrs)),
        Or(f) => f.iter().any(|f| match_filter(f, attrs)),
        Not(f) => !match_filter(f, attrs),
        Equality(k, v) => attrs.iter().any(|(key, vals)| {
            // key is case insensitive
            // TODO: value? need schema
            if key.eq_ignore_ascii_case(k) {
                vals.contains(v)
            } else {
                false
            }
        }),
        Substring(k, filters) => {
            if let Some(vals) = attrs.get(k) {
                vals.iter().any(|val| {
                    filters.iter().all(|f| match f {
                        LdapSubstringFilter::Initial(s) => val.starts_with(s),
                        LdapSubstringFilter::Any(s) => val.contains(s),
                        LdapSubstringFilter::Final(s) => val.ends_with(s),
                    })
                })
            } else {
                false
            }
        }
        Present(k) => attrs.contains_key(k),
    }
}

async fn handle_msg(client: &mut Client, msg: StructureTag) -> anyhow::Result<Vec<LdapMsg>> {
    use ldap3_server::proto::LdapOp::*;
    let msg = match LdapMsg::try_from(msg) {
        Ok(msg) => msg,
        Err(_) => {
            info!("Fail to parse msg");
            return Ok(vec![DisconnectionNotice::gen(
                LdapResultCode::ProtocolError,
                "Unable to parse message",
            )]);
        }
    };
    match msg.op {
        BindRequest(req) => {
            // https://tools.ietf.org/html/rfc4511#section-4.2
            info!("Got bind request to {:?} with cred {:?}", req.dn, req.cred);

            let resp = LdapMsg {
                msgid: msg.msgid,
                op: BindResponse(LdapBindResponse {
                    res: LdapResult {
                        code: LdapResultCode::Success,
                        matcheddn: req.dn,
                        message: format!("Bind success"),
                        referral: vec![],
                    },
                    saslcreds: None,
                }),
                ctrl: vec![],
            };

            Ok(vec![resp])
        }
        AddRequest(req) => {
            // https://tools.ietf.org/html/rfc4511#section-4.7
            info!(
                "Got add request to {} with attrs {:?}",
                req.dn, req.attributes
            );

            let mut parts: Vec<&str> = req.dn.split(",").map(str::trim).collect();
            parts.reverse();

            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            for attr in &req.attributes {
                map.insert(attr.atype.clone(), attr.vals.clone());
            }

            let value = serde_json::to_vec(&map)?;

            info!("Put data to etcd");
            let key = parts.join(",");
            info!("Key is {}", key);
            let mut txn = Txn::new();
            // create revision > 0 means exists
            if parts.len() > 1 {
                // The immediate superior (parent) of an
                // object or alias entry to be added MUST exist.
                let parent = parts[..parts.len() - 1].join(",");
                info!("Parent DN is {}", parent);
                txn = txn.when(vec![
                    Compare::create_revision(parent, etcd_client::CompareOp::Greater, 0),
                    Compare::create_revision(key.clone(), etcd_client::CompareOp::Equal, 0),
                ]);
            } else {
                txn = txn.when(vec![Compare::create_revision(
                    key.clone(),
                    etcd_client::CompareOp::Equal,
                    0,
                )]);
            }
            txn = txn.and_then(vec![TxnOp::put(key.clone(), value, None)]);
            txn = txn.or_else(vec![TxnOp::get(key, None)]);
            let ret = client.txn(txn).await?;

            let (code, message) = if ret.succeeded() {
                (LdapResultCode::Success, "Add entry success")
            } else {
                match ret.op_responses().get(0) {
                    Some(TxnOpResponse::Get(resp)) => {
                        if resp.count() > 0 {
                            // already exists
                            (LdapResultCode::EntryAlreadyExists, "Entry already exists")
                        } else {
                            // parent does not exist
                            (LdapResultCode::NoSuchObject, "Parent DN does not exist")
                        }
                    }
                    _ => (LdapResultCode::Other, "Internal error"),
                }
            };
            info!("Add resp code {:?} message {}", code, message);

            let resp = LdapMsg {
                msgid: msg.msgid,
                op: AddResponse(LdapResult {
                    code,
                    matcheddn: req.dn,
                    message: message.to_string(),
                    referral: vec![],
                }),
                ctrl: vec![],
            };

            Ok(vec![resp])
        }
        SearchRequest(req) => {
            // https://tools.ietf.org/html/rfc4511#section-4.5.1

            // server specific data
            // https://tools.ietf.org/html/rfc4512#section-5.1
            if req.base == "" && req.scope == LdapSearchScope::Base {
                if req.filter == LdapFilter::Present("objectclass".to_string()) {
                    info!("Got server specific data request {:?}", req);
                    let entry = LdapMsg {
                        msgid: msg.msgid,
                        op: SearchResultEntry(LdapSearchResultEntry {
                            dn: "".to_string(),
                            attributes: vec![LdapPartialAttribute {
                                atype: "supportedSASLMechanisms".to_string(),
                                vals: vec![],
                            }],
                        }),
                        ctrl: vec![],
                    };

                    let done = LdapMsg {
                        msgid: msg.msgid,
                        op: SearchResultDone(LdapResult {
                            code: LdapResultCode::Success,
                            matcheddn: "".to_string(),
                            message: "Return server specific data".to_string(),
                            referral: vec![],
                        }),
                        ctrl: vec![],
                    };

                    return Ok(vec![entry, done]);
                }
            }
            info!("Got search request {:?}", req);

            let mut resp = vec![];

            // query
            let mut parts: Vec<&str> = req.base.split(",").map(str::trim).collect();
            parts.reverse();
            let prefix = parts.join(",") + ",";
            if req.scope == LdapSearchScope::Subtree {
                let entries = client
                    .get(prefix, Some(GetOptions::new().with_prefix()))
                    .await?;
                for kv in entries.kvs() {
                    let mut actual_key: Vec<&str> = kv.key_str()?.split(",").collect();
                    actual_key.reverse();
                    let attrs: HashMap<String, Vec<String>> = serde_json::from_slice(kv.value())?;

                    if !match_filter(&req.filter, &attrs) {
                        continue;
                    }

                    let entry = LdapMsg {
                        msgid: msg.msgid,
                        op: SearchResultEntry(LdapSearchResultEntry {
                            dn: actual_key.join(","),
                            attributes: attrs
                                .iter()
                                .filter(|(k, _v)| req.attrs.contains(k))
                                .map(|(k, v)| LdapPartialAttribute {
                                    atype: k.clone(),
                                    vals: v.clone(),
                                })
                                .collect(),
                        }),
                        ctrl: vec![],
                    };
                    resp.push(entry);
                }
            }

            let done = LdapMsg {
                msgid: msg.msgid,
                op: SearchResultDone(LdapResult {
                    code: LdapResultCode::Success,
                    matcheddn: req.base,
                    message: "Return search result".to_string(),
                    referral: vec![],
                }),
                ctrl: vec![],
            };
            info!("Return {} search entries", resp.len());
            resp.push(done);
            Ok(resp)
        }
        AbandonRequest(id) => {
            // https://tools.ietf.org/html/rfc4511#section-4.11
            // do nothing
            info!("Got abandon request to {}", id);
            Ok(vec![])
        }
        DelRequest(dn) => {
            // https://tools.ietf.org/html/rfc4511#section-4.8
            let mut parts: Vec<&str> = dn.split(",").map(str::trim).collect();
            parts.reverse();
            let key = parts.join(",");
            let res = client.delete(key, None).await?;
            let (code, message) = if res.deleted() > 0 {
                (LdapResultCode::Success, "Deletion success")
            } else {
                (
                    LdapResultCode::NoSuchObject,
                    "The key to delete is not found",
                )
            };

            let resp = LdapMsg {
                msgid: msg.msgid,
                op: DelResponse(LdapResult {
                    code,
                    matcheddn: dn,
                    message: message.to_string(),
                    referral: vec![],
                }),
                ctrl: vec![],
            };
            Ok(vec![resp])
        }
        UnbindRequest => {
            // https://tools.ietf.org/html/rfc4511#section-4.3
            info!("Got unbind request");
            Ok(vec![DisconnectionNotice::gen(
                LdapResultCode::Success,
                "Unbind",
            )])
        }
        msg => {
            info!("Got unknown message: {:#?}", msg);
            Ok(vec![DisconnectionNotice::gen(
                LdapResultCode::ProtocolError,
                "Unknown message",
            )])
        }
    }
}

async fn ldap_handler(mut client: Client, mut socket: TcpStream) -> anyhow::Result<()> {
    // receive message handling
    let mut buffer = vec![0u8; 1024];
    let mut len = 0;
    let mut parser = Parser::new();
    loop {
        let bytes = socket.read(&mut buffer[len..]).await?;
        if bytes == 0 {
            // connection closed
            return Ok(());
        }
        len += bytes;

        let (size, msg) = match parser.handle(Input::Element(&buffer)) {
            ConsumerState::Continue(_) => continue,
            ConsumerState::Error(_) => {
                return Err(anyhow!("Got error when parsing asn1 ber message"));
            }
            ConsumerState::Done(size, msg) => (size, msg.clone()),
        };

        let size = *match size {
            Move::Await(_) => continue,
            Move::Seek(_) => unimplemented!(),
            Move::Consume(s) => s,
        };
        len -= size;

        // move buffer
        buffer.copy_within(size..len + size, 0);

        for resp in handle_msg(&mut client, msg).await? {
            let tag: StructureTag = resp.into();
            let mut resp_buffer = BytesMut::with_capacity(4096);
            lber::write::encode_into(&mut resp_buffer, tag)?;
            socket.write_all(&resp_buffer).await?;
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let matches = App::new("daccountd")
        .arg(
            Arg::with_name("name")
                .short("n")
                .long("name")
                .value_name("NAME")
                .help("Override node name")
                .takes_value(true),
        )
        .get_matches();

    let mut buffer = vec![];
    let mut file = File::open("config.toml")?;
    file.read_to_end(&mut buffer)?;
    let config: Config = toml::from_slice(&buffer)?;

    let name = matches
        .value_of("name")
        .map(|s| s.to_string())
        .or(config.name)
        .unwrap_or_else(|| gethostname().to_string_lossy().to_string());
    info!("This node name is {}", name);

    if let Some(host) = config.host.iter().find(|h| h.name == name) {
        let data = host.data.clone().unwrap_or(format!("data-{}", name));
        let log = host.log.clone().unwrap_or(format!("etcd-{}.log", name));
        let initial_cluster = config
            .host
            .iter()
            .map(|h| format!("{}={}", h.name, h.advertise_peer))
            .collect::<Vec<String>>()
            .join(",");
        unsafe {
            Run(
                go_string(&data),
                go_string(&host.name),
                go_string(&initial_cluster),
                go_string("info"),
                go_string(&log),
                go_string(&host.advertise_client),
                go_string(&host.listen_client),
                go_string(&host.advertise_peer),
                go_string(&host.listen_peer),
            );
        }
        info!(
            "Etcd server started at peer {} client {} initial cluster {}",
            host.listen_peer, host.listen_client, initial_cluster
        );
        info!("Initial cluster is {}", initial_cluster);
        info!("Etcd data is located at {}", data);
        info!("Etcd is logged to {}", log);

        let client = Client::connect([&host.listen_client], None).await?;

        // start ldap server
        if let Some(ldap) = &host.ldap {
            let listener = TcpListener::bind(&ldap).await?;
            loop {
                let (socket, addr) = listener.accept().await?;
                let client = client.clone();
                tokio::spawn(async move {
                    info!("Got LDAP connection from {}", addr);
                    if let Err(err) = ldap_handler(client, socket).await {
                        warn!("Got error {} for client {}", err, addr);
                    }
                });
            }
        } else {
            loop {
                yield_now().await;
            }
        }
    } else {
        error!("No matching configuration found for host {}", name);
    }
    Ok(())
}
