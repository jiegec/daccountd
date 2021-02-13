use std::process::Command;

extern crate bindgen;

// ref: https://radu-matei.com/blog/from-go-to-rust-static-linking-ffi/
fn main() {
    println!("cargo:rustc-link-search=native=target");
    println!("cargo:rustc-link-lib=static=daccountd");
    println!("cargo:rerun-if-changed=go/etcd.go");

    Command::new("make").spawn().expect("Make should success");

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-flags=-l framework=CoreFoundation -l framework=Security");
    }
}
