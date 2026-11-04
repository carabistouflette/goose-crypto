// SPDX-License-Identifier: Apache-2.0
import crypto from "../..";
// Development candidate; pending HTTP clock/progress corrections and final CI.
import http from "carabistouflette/goose-http@e0ca6b70836d6c800f6ed24b7a369f81a0228b69";
import fs from "carabistouflette/goose-fs@cd0bd29c78c435caaebf75bfecd8e3e2083636eb";
import json_codec from "carabistouflette/goose-json@3fa7b5275399641f8069698b6c097ea66cef7929";
import signals from "./signals";
import .workflow;
import std;
import os;

fn decimal_limit(text: const u8[:]) -> i64, bool {
    if text.len < 1 || text.len > 10 { return 0, false; }
    var value: i64 = 0;
    for c in text {
        if c < '0' || c > '9' { return 0, false; }
        value = value * 10 + c - '0';
        if value > download::MAX_DOWNLOAD_BYTES { return 0, false; }
    }
    return value, true;
}
fn main() {
    let argv = args();
    if argv.len != 9 {
        write_stderr("usage: download METADATA_ABSOLUTE_PATH SIGNATURE_HEX TRUSTED_KEY_HEX EXPECTED_HTTPS_URL PRIVATE_PARENT STAGING_LEAF FINAL_LEAF BYTE_LIMIT\n");
        exit(2);
    }
    let limit, valid = decimal_limit(argv[8]);
    var result = download::Result { .. };
    if !valid {
        result.stage = download::Stage.InvalidInput;
    } else {
        let started = download_signals::start();
        if started != 0 {
            result.stage = download::Stage.GuardStart;
            result.os_error = started;
        } else {
            let request = download::Request { metadata_path: argv[1], signature_hex: argv[2],
                trusted_key_hex: argv[3], expected_url: argv[4], private_parent: argv[5],
                staging_leaf: argv[6], final_leaf: argv[7], byte_limit: limit };
            result = download::execute(request);
        }
        // Also restores a partially installed guard after failed start. No
        // filesystem or HTTP resource remains when CLI exit is invoked below.
        result.cleanup_guard_error = download_signals::stop();
        if result.cleanup_guard_error != 0 && result.stage == download::Stage.None {
            result.stage = download::Stage.GuardStop;
            result.os_error = result.cleanup_guard_error;
        }
    }
    let code = download::exit_code(result);
    if code == 0 { print(download::describe(result)); }
    else { write_stderr(str(download::describe(result), "\n")); }
    exit(code);
}
