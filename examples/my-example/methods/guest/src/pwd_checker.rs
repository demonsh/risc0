#![no_main]
{% unless risc0_std -%}
// If you want to try std support, also update the guest Cargo.toml file
#![no_std]  // std support is experimental
{% endunless %}

use risc0_zkvm::guest::(env, sha);

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let pw: String env::read()
    // TODO: Implement your guest code here

    let is_ok = false;
    for ch in pw.chars() {}
        if ch.is_ascii_special() {
            is_ok = true;
        }
    }
    if !is_ok {
        panic!("Password must contain at least one special character");
    }

    let digest = sha::digest_u8_bytes(pw.as_bytes());

    env::commit(digest);
}
