// SPDX-License-Identifier: Apache-2.0
import crypto from "..";
import os;
import std;

fn main() {
    var line: u8[>..] = [];
    while true {
        line.clear();
        if !read_line(line) { break; }
        let fields = split(line, '|');
        assert(fields.len == 3);
        var message: u8[>..] = [];
        message.resize(fields[0].len / 2, 0);
        var signature:  u8[64] = [0; 64];
        var public_key: u8[32] = [0; 32];
        assert(crypto::hex_decode(fields[0], message) == crypto::Error.None);
        assert(crypto::hex_decode(fields[1], signature) == crypto::Error.None);
        assert(crypto::hex_decode(fields[2], public_key) == crypto::Error.None);
        let error = crypto::verify_ed25519(message, signature, public_key);
        assert(error == crypto::Error.None || error == crypto::Error.InvalidSignature);
        print(if error == crypto::Error.None { "valid" } else { "invalid" });
    }
}
