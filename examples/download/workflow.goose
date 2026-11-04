// SPDX-License-Identifier: Apache-2.0
namespace download;
import crypto;
import http;
import fs;
import json_codec;
import signals;
import std;

const MAX_DOWNLOAD_BYTES: i64 = 1073741824;
// This example targets Linux, where ENOENT is 2. Other errors are not absence.
const LINUX_ENOENT: i64 = 2;
const CHUNK_BYTES:  i64 = 65536;

root struct Metadata { url: json_codec::Text, sha256: json_codec::Text }
struct Request {
    metadata_path:   const u8[:],
    signature_hex:   const u8[:],
    trusted_key_hex: const u8[:],
    expected_url:    const u8[:],
    private_parent:  const u8[:],
    staging_leaf:    const u8[:],
    final_leaf:      const u8[:],
    byte_limit:      i64,
}
enum Stage {
    None, InvalidInput, MetadataRead, Signature, SignatureBackend, Json, Url,
    DigestInput, Cancelled, ContextOpen, RootOpen, ParentPolicy, StagingCheck,
    StagingExists, FinalCheck, FinalExists, StagingOpen, HttpOpen, HttpRead,
    HttpStatus, BodyLimit, Chunk, HashInit, HashUpdate, HashFinish, DigestMismatch,
    Write, FileSync, FileClose, HttpClose, Publish, Cleanup, GuardStart, GuardStop,
}
struct Result {
    stage:                Stage             = Stage.None,
    os_error:             i64               = 0,
    http_status:          http::Status      = http::Status { .. },
    signal_number:        i64               = 0,
    publication:          fs::RenameOutcome = fs::RenameOutcome.NotAttempted,
    parents_synced:       bool              = false,
    rename_cleanup_error: i64               = 0,
    cleanup_http:         http::Status      = http::Status { .. },
    cleanup_file:         fs::Status        = fs::Status { .. },
    cleanup_staging:      fs::Status        = fs::Status { .. },
    cleanup_root:         fs::Status        = fs::Status { .. },
    cleanup_context:      fs::Status        = fs::Status { .. },
    cleanup_guard_error:  i64               = 0,
    residue_may_remain:   bool              = false,
    received_bytes:       i64               = 0,
    written_bytes:        i64               = 0,
}
struct Resources {
    context:           fs::Context        = fs::Context { .. },
    root:              fs::Root           = fs::Root { .. },
    file:              fs::File           = fs::File { .. },
    stream:            http::StreamHandle = http::StreamHandle { .. },
    stream_owned:      bool               = false,
    staging_may_exist: bool               = false,
}

fn fail(result: Result&, stage: Stage, os_error: i64 = 0) -> bool {
    if result.stage == Stage.None { result.stage = stage; result.os_error = os_error; }
    return false;
}
fn cancellation(result: Result&) -> bool {
    let number = download_signals::received();
    if number == 0 { return false; }
    if result.stage == Stage.None { result.stage = Stage.Cancelled; result.signal_number = number; }
    return true;
}
fn valid_leaf(name: const u8[:]) -> bool {
    if name.len < 1 || name.len > 255 || name == "." || name == ".." { return false; }
    for c in name { if c == 0 || c == '/' { return false; } }
    return true;
}
fn missing(status: fs::Status) -> bool {
    return status.error == fs::Error.SystemError && status.os_error == LINUX_ENOENT;
}
fn absent(root: fs::Root, leaf: const u8[:], result: Result&, check_stage: Stage, exists_stage: Stage) -> bool {
    var info = fs::Metadata { .. };
    let status = fs::metadata_at(root, leaf, info);
    if status.error == fs::Error.None { return fail(result, exists_stage); }
    if missing(status) { return true; }
    return fail(result, check_stage, status.os_error);
}
fn authenticate(request: const Request&, expected: u8[:], result: Result&) -> bool {
    if !fs::valid_path(request.metadata_path) || !fs::valid_path(request.private_parent) ||
        !valid_leaf(request.staging_leaf) || !valid_leaf(request.final_leaf) ||
        request.staging_leaf == request.final_leaf || request.expected_url.len > 8192 ||
        !starts_with(request.expected_url, "https://") || request.byte_limit < 0 ||
        request.byte_limit > MAX_DOWNLOAD_BYTES || request.byte_limit > crypto::MAX_SHA256_BYTES {
        return fail(result, Stage.InvalidInput);
    }
    var signature: u8[64] = [0; 64];
    var key:       u8[32] = [0; 32];
    if crypto::hex_decode(request.signature_hex, signature) != crypto::Error.None ||
        crypto::hex_decode(request.trusted_key_hex, key) != crypto::Error.None {
        return fail(result, Stage.InvalidInput);
    }
    if cancellation(result) { return false; }
    var raw: u8[>..] = [];
    let read = fs::read(request.metadata_path, 16384, raw);
    if read.error != fs::Error.None { return fail(result, Stage.MetadataRead, read.os_error); }
    let verified = crypto::verify_ed25519(raw, signature, key);
    if verified == crypto::Error.InvalidSignature { return fail(result, Stage.Signature); }
    if verified != crypto::Error.None { return fail(result, Stage.SignatureBackend); }
    // Authenticate original bytes before parsing, network setup or file mutation.
    var metadata = Metadata { .. };
    let error = json_codec::deserialize_into(raw, metadata);
    if error.len != 0 { return fail(result, Stage.Json); }
    if metadata.url.bytes != request.expected_url { return fail(result, Stage.Url); }
    if crypto::hex_decode(metadata.sha256.bytes, expected) != crypto::Error.None {
        return fail(result, Stage.DigestInput);
    }
    return !cancellation(result);
}
fn prepare(request: const Request&, resources: Resources&, result: Result&) -> bool {
    if cancellation(result) { return false; }
    let context, created = fs::create_context();
    resources.context = context;
    if created.error != fs::Error.None { return fail(result, Stage.ContextOpen, created.os_error); }
    let root, opened = fs::open_root(context, request.private_parent);
    resources.root = root;
    if opened.error != fs::Error.None { return fail(result, Stage.RootOpen, opened.os_error); }
    var info = fs::Metadata { .. };
    let inspected = fs::root_metadata(root, info);
    if inspected.error != fs::Error.None { return fail(result, Stage.ParentPolicy, inspected.os_error); }
    // This rejects accidentally shared directories; caller still promises no
    // other writers, including same-UID writers, for the whole workflow.
    if info.kind != fs::Kind.Directory || (info.permissions & 63) != 0 { return fail(result, Stage.ParentPolicy); }
    if !absent(root, request.staging_leaf, result, Stage.StagingCheck, Stage.StagingExists) ||
        !absent(root, request.final_leaf, result, Stage.FinalCheck, Stage.FinalExists) { return false; }
    if cancellation(result) { return false; }
    // A failed CreateNew can still create an entry. Prior absence plus the
    // private/no-other-writers contract establishes possible ownership here.
    resources.staging_may_exist = true;
    let file, file_opened = fs::open_file_at(root, request.staging_leaf,
        fs::OpenOptions { access: fs::Access.Write, creation: fs::Creation.CreateNew, permissions: 384 });
    resources.file = file;
    if file_opened.error != fs::Error.None { return fail(result, Stage.StagingOpen, file_opened.os_error); }
    return !cancellation(result);
}
fn close_http(resources: Resources&, result: Result&) -> bool {
    if !resources.stream_owned { return true; }
    result.cleanup_http = http::close_stream(resources.stream);
    resources.stream_owned = false;
    if result.cleanup_http.error != http::Error.None { return fail(result, Stage.HttpClose); }
    return true;
}
fn accept_chunk(resources: Resources&, request: const Request&, chunk: const u8[:], hash: crypto::Sha256&, result: Result&) -> bool {
    if chunk.len < 1 || chunk.len > CHUNK_BYTES { return fail(result, Stage.Chunk); }
    if chunk.len > request.byte_limit - result.received_bytes { return fail(result, Stage.BodyLimit); }
    result.received_bytes += chunk.len;
    if crypto::update(hash, chunk) != crypto::Error.None { return fail(result, Stage.HashUpdate); }
    var offset: i64 = 0;
    while offset < chunk.len {
        if cancellation(result) { return false; }
        let end = offset + min(chunk.len - offset, fs::MAX_BYTES);
        let written = fs::write_all(resources.file, chunk[offset..end]);
        if written.bytes >= 0 && written.bytes <= end - offset { result.written_bytes += written.bytes; }
        if written.status.error != fs::Error.None || written.bytes != end - offset {
            return fail(result, Stage.Write, written.status.os_error);
        }
        offset = end;
    }
    return true;
}
fn transfer(resources: Resources&, request: const Request&, expected: const u8[:], result: Result&) -> bool {
    if cancellation(result) { return false; }
    let options = http::StreamOptions { timeout_ms: 300000, connect_timeout_ms: 10000,
        chunk_limit: CHUNK_BYTES, body_limit: request.byte_limit, header_limit: 16384 };
    resources.stream_owned = true;
    let opened = http::open_stream(request.expected_url, options, resources.stream);
    result.http_status = opened;
    if opened.error != http::Error.None { return fail(result, Stage.HttpOpen); }
    var hash = crypto::Sha256 { .. };
    if crypto::init(hash) != crypto::Error.None { return fail(result, Stage.HashInit); }
    var chunk:   u8[>..] = [];
    var headers: u8[>..] = [];
    while true {
        if cancellation(result) { return false; }
        let step, status = http::read_chunk(resources.stream, chunk, headers, 20);
        result.http_status = status;
        if cancellation(result) { return false; }
        if status.error != http::Error.None { return fail(result, Stage.HttpRead); }
        if headers.len > 16384 { return fail(result, Stage.HttpRead); }
        if step == http::StreamStep.Chunk {
            if !accept_chunk(resources, request, chunk, hash, result) { return false; }
        } else {
            if chunk.len != 0 { return fail(result, Stage.Chunk); }
            if step == http::StreamStep.IdleTimeout { continue; }
            if step == http::StreamStep.Cancelled { return fail(result, Stage.Cancelled); }
            if step != http::StreamStep.Done { return fail(result, Stage.HttpRead); }
            // Only clean completion with final HTTP 200 authorizes digest use.
            if resources.stream.status_code != 200 || (status.status_code != 0 && status.status_code != 200) {
                return fail(result, Stage.HttpStatus);
            }
            break;
        }
    }
    if !close_http(resources, result) || cancellation(result) { return false; }
    var digest: u8[32] = [0; 32];
    if crypto::finish(hash, digest) != crypto::Error.None { return fail(result, Stage.HashFinish); }
    if digest[..] != expected { return fail(result, Stage.DigestMismatch); }
    return true;
}
fn publish(resources: Resources&, request: const Request&, result: Result&) -> bool {
    if cancellation(result) { return false; }
    let synced = fs::sync_file(resources.file, true);
    if synced.error != fs::Error.None { return fail(result, Stage.FileSync, synced.os_error); }
    result.cleanup_file = fs::close_file(resources.file);
    // Failed close still consumes the token. Never retry the File close.
    resources.file = fs::File { .. };
    if result.cleanup_file.error != fs::Error.None { return fail(result, Stage.FileClose, result.cleanup_file.os_error); }
    // Signals after this last decision cannot revoke the publication syscall.
    if cancellation(result) { return false; }
    let renamed = fs::rename_at(resources.root, request.staging_leaf, request.final_leaf,
        fs::RenameOptions { policy: fs::RenamePolicy.NoReplace, sync_parents: true });
    result.publication = renamed.outcome;
    result.parents_synced = renamed.parents_synced;
    result.rename_cleanup_error = renamed.cleanup_os_error;
    if renamed.outcome == fs::RenameOutcome.Applied { resources.staging_may_exist = false; }
    if renamed.status.error != fs::Error.None || renamed.outcome != fs::RenameOutcome.Applied ||
        !renamed.parents_synced || renamed.cleanup_os_error != 0 {
        return fail(result, Stage.Publish, renamed.status.os_error);
    }
    return true;
}
fn cleanup(resources: Resources&, request: const Request&, result: Result&) {
    close_http(resources, result);
    if resources.file.id != 0 {
        result.cleanup_file = fs::close_file(resources.file);
        resources.file = fs::File { .. };
    }
    if resources.staging_may_exist && result.publication == fs::RenameOutcome.NotAttempted {
        result.cleanup_staging = fs::remove_file_at(resources.root, request.staging_leaf);
        if missing(result.cleanup_staging) { result.cleanup_staging = fs::Status { .. }; }
        if result.cleanup_staging.error == fs::Error.None { resources.staging_may_exist = false; }
    }
    // Unknown preserves possible staging residue. Applied is never rolled back.
    result.residue_may_remain = resources.staging_may_exist;
    if resources.root.id != 0 {
        result.cleanup_root = fs::close_root(resources.root);
        resources.root = fs::Root { .. };
    }
    if resources.context.id != 0 {
        result.cleanup_context = fs::close_context(resources.context);
        resources.context = fs::Context { .. };
    }
    if result.stage == Stage.None && (result.cleanup_http.error != http::Error.None ||
        result.cleanup_file.error != fs::Error.None || result.cleanup_staging.error != fs::Error.None ||
        result.cleanup_root.error != fs::Error.None || result.cleanup_context.error != fs::Error.None) {
        fail(result, Stage.Cleanup);
    }
}
// Caller owns the signal guard; cleanup completes before this normal return.
fn execute(request: const Request&) -> Result {
    var result = Result { .. };
    var expected: u8[32] = [0; 32];
    if !authenticate(request, expected, result) { return result; }
    var resources = Resources { .. };
    if prepare(request, resources, result) && transfer(resources, request, expected, result) {
        publish(resources, request, result);
    }
    cleanup(resources, request, result);
    return result;
}
fn stage_name(stage: Stage) -> const u8[:] {
    if stage == Stage.None { return "None"; }
    if stage == Stage.InvalidInput { return "InvalidInput"; }
    if stage == Stage.MetadataRead { return "MetadataRead"; }
    if stage == Stage.Signature { return "Signature"; }
    if stage == Stage.SignatureBackend { return "SignatureBackend"; }
    if stage == Stage.Json { return "Json"; }
    if stage == Stage.Url { return "Url"; }
    if stage == Stage.DigestInput { return "DigestInput"; }
    if stage == Stage.Cancelled { return "Cancelled"; }
    if stage == Stage.ContextOpen { return "ContextOpen"; }
    if stage == Stage.RootOpen { return "RootOpen"; }
    if stage == Stage.ParentPolicy { return "ParentPolicy"; }
    if stage == Stage.StagingCheck { return "StagingCheck"; }
    if stage == Stage.StagingExists { return "StagingExists"; }
    if stage == Stage.FinalCheck { return "FinalCheck"; }
    if stage == Stage.FinalExists { return "FinalExists"; }
    if stage == Stage.StagingOpen { return "StagingOpen"; }
    if stage == Stage.HttpOpen { return "HttpOpen"; }
    if stage == Stage.HttpRead { return "HttpRead"; }
    if stage == Stage.HttpStatus { return "HttpStatus"; }
    if stage == Stage.BodyLimit { return "BodyLimit"; }
    if stage == Stage.Chunk { return "Chunk"; }
    if stage == Stage.HashInit { return "HashInit"; }
    if stage == Stage.HashUpdate { return "HashUpdate"; }
    if stage == Stage.HashFinish { return "HashFinish"; }
    if stage == Stage.DigestMismatch { return "DigestMismatch"; }
    if stage == Stage.Write { return "Write"; }
    if stage == Stage.FileSync { return "FileSync"; }
    if stage == Stage.FileClose { return "FileClose"; }
    if stage == Stage.HttpClose { return "HttpClose"; }
    if stage == Stage.Publish { return "Publish"; }
    if stage == Stage.Cleanup { return "Cleanup"; }
    if stage == Stage.GuardStart { return "GuardStart"; }
    return "GuardStop";
}
fn publication_name(outcome: fs::RenameOutcome) -> const u8[:] {
    if outcome == fs::RenameOutcome.Applied { return "Applied"; }
    if outcome == fs::RenameOutcome.Unknown { return "Unknown"; }
    return "NotAttempted";
}
// Diagnostics contain only fixed labels, booleans and numbers, never caller
// names, URLs, metadata, signatures or key material.
fn describe(result: const Result&) -> u8[>..] {
    return str("download: stage=", stage_name(result.stage),
        " publication=", publication_name(result.publication),
        " os_error=", result.os_error,
        " http_failed=", result.http_status.error != http::Error.None,
        " http_transport=", result.http_status.transport_code,
        " http_status=", result.http_status.status_code,
        " signal=", result.signal_number,
        " parents_synced=", result.parents_synced,
        " rename_cleanup_error=", result.rename_cleanup_error,
        " residue_may_remain=", result.residue_may_remain,
        " received_bytes=", result.received_bytes,
        " written_bytes=", result.written_bytes,
        " cleanup_http_failed=", result.cleanup_http.error != http::Error.None,
        " cleanup_http_transport=", result.cleanup_http.transport_code,
        " cleanup_file_failed=", result.cleanup_file.error != fs::Error.None,
        " cleanup_file_errno=", result.cleanup_file.os_error,
        " cleanup_staging_failed=", result.cleanup_staging.error != fs::Error.None,
        " cleanup_staging_errno=", result.cleanup_staging.os_error,
        " cleanup_root_failed=", result.cleanup_root.error != fs::Error.None,
        " cleanup_root_errno=", result.cleanup_root.os_error,
        " cleanup_context_failed=", result.cleanup_context.error != fs::Error.None,
        " cleanup_context_errno=", result.cleanup_context.os_error,
        " cleanup_guard_error=", result.cleanup_guard_error);
}
fn exit_code(result: const Result&) -> i64 {
    if result.stage == Stage.None { return 0; }
    if result.stage == Stage.Cancelled { return if result.signal_number == 15 { 143 } else { 130 }; }
    return 1;
}
