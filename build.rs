fn main() {
    // Advertise the versioned soname on the shared object. Symbol-export visibility
    // is handled by rustc's own cdylib version script (only our `#[no_mangle]` pub
    // `rsi_*` functions are exported; everything else is hidden).
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,librsi.so.0");
    println!("cargo:rerun-if-changed=build.rs");
}
