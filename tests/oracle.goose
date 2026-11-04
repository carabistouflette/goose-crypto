// SPDX-License-Identifier: Apache-2.0
import crypto from "..";
import os;
import std;

fn main() {
    var line: u8[>..] = [];
    while true {
        line.clear();
        if !read_line(line) { break; }
        var message: u8[>..] = [];
        message.resize(line.len / 2, 0);
        assert(crypto::hex_decode(line, message) == crypto::Error.None);
        var one:      u8[32] = [0; 32];
        var streamed: u8[32] = [0; 32];
        assert(crypto::sha256(message, one) == crypto::Error.None);
        var state = crypto::Sha256 { .. };
        assert(crypto::init(state) == crypto::Error.None);
        var at: i64 = 0;
        while at < message.len {
            let end = min(message.len, at + 1 + at % 257);
            assert(crypto::update(state, message[at..end]) == crypto::Error.None);
            at = end;
        }
        assert(crypto::finish(state, streamed) == crypto::Error.None);
        assert(one == streamed);
        var hex: u8[64] = [0; 64];
        assert(crypto::hex_encode(one, hex) == crypto::Error.None);
        print(hex);
    }
}
