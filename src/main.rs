#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("../target/bindings.rs");

pub fn go_string(s: &str) -> GoString {
    GoString {
        p: s.as_bytes().as_ptr() as *const i8,
        n: s.len() as isize,
    }
}

fn main() {
    let data = "data";
    let name = "node1";
    let initialCluster = "node1=http://127.0.0.1:30012";
    let advertiseClient = "http://127.0.0.1:30011";
    let listenClient = "http://127.0.0.1:30011";
    let advertisePeer = "http://127.0.0.1:30012";
    let listenPeer = "http://127.0.0.1:30012";
    unsafe {
        Run(
            go_string(data),
            go_string(name),
            go_string(initialCluster),
            go_string("info"),
            go_string(advertiseClient),
            go_string(listenClient),
            go_string(advertisePeer),
            go_string(listenPeer),
        );
    }
    loop {}
}
