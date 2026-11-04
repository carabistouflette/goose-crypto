// SPDX-License-Identifier: Apache-2.0
import crypto from "..";
import std;
fn main() {
    var digest: u8[32] = [0; 32];
    var hex:    u8[64] = [0; 64];
    assert(crypto::sha256("abc", digest[..]) == crypto::Error.None);
    assert(crypto::hex_encode(digest[..], hex[..]) == crypto::Error.None);
    print(hex[..]);
}
