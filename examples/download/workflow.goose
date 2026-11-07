// SPDX-License-Identifier: Apache-2.0
namespace download;
import artifact;
import http;
import fs;
import signals;
import std;

const MAX_DOWNLOAD_BYTES: i64 = artifact::MAX_DOWNLOAD_BYTES;

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
// The shared library owns verification, streaming, publication and cleanup.
// This adapter retains the example CLI's diagnostics and signal policy.
fn local_stage(stage: artifact::Stage) -> Stage {
    if stage == artifact::Stage.None { return Stage.None; }
    if stage == artifact::Stage.InvalidInput { return Stage.InvalidInput; }
    if stage == artifact::Stage.MetadataRead { return Stage.MetadataRead; }
    if stage == artifact::Stage.Signature { return Stage.Signature; }
    if stage == artifact::Stage.SignatureBackend { return Stage.SignatureBackend; }
    if stage == artifact::Stage.Json { return Stage.Json; }
    if stage == artifact::Stage.Url { return Stage.Url; }
    if stage == artifact::Stage.DigestInput { return Stage.DigestInput; }
    if stage == artifact::Stage.Cancelled { return Stage.Cancelled; }
    if stage == artifact::Stage.ContextOpen { return Stage.ContextOpen; }
    if stage == artifact::Stage.RootOpen { return Stage.RootOpen; }
    if stage == artifact::Stage.ParentPolicy { return Stage.ParentPolicy; }
    if stage == artifact::Stage.StagingCheck { return Stage.StagingCheck; }
    if stage == artifact::Stage.StagingExists { return Stage.StagingExists; }
    if stage == artifact::Stage.FinalCheck { return Stage.FinalCheck; }
    if stage == artifact::Stage.FinalExists { return Stage.FinalExists; }
    if stage == artifact::Stage.StagingOpen { return Stage.StagingOpen; }
    if stage == artifact::Stage.HttpOpen { return Stage.HttpOpen; }
    if stage == artifact::Stage.HttpRead { return Stage.HttpRead; }
    if stage == artifact::Stage.HttpStatus { return Stage.HttpStatus; }
    if stage == artifact::Stage.BodyLimit { return Stage.BodyLimit; }
    if stage == artifact::Stage.Chunk { return Stage.Chunk; }
    if stage == artifact::Stage.HashInit { return Stage.HashInit; }
    if stage == artifact::Stage.HashUpdate { return Stage.HashUpdate; }
    if stage == artifact::Stage.HashFinish { return Stage.HashFinish; }
    if stage == artifact::Stage.DigestMismatch { return Stage.DigestMismatch; }
    if stage == artifact::Stage.Write { return Stage.Write; }
    if stage == artifact::Stage.FileSync { return Stage.FileSync; }
    if stage == artifact::Stage.FileClose { return Stage.FileClose; }
    if stage == artifact::Stage.HttpClose { return Stage.HttpClose; }
    if stage == artifact::Stage.Publish { return Stage.Publish; }
    if stage == artifact::Stage.Cleanup { return Stage.Cleanup; }
    return Stage.Cleanup;
}
fn execute(request: const Request&) -> Result {
    let shared_request = artifact::Request {
        metadata_path:   request.metadata_path, signature_hex: request.signature_hex,
        trusted_key_hex: request.trusted_key_hex, expected_url: request.expected_url,
        private_parent:  request.private_parent, staging_leaf: request.staging_leaf,
        final_leaf:      request.final_leaf, byte_limit: request.byte_limit,
    };
    let shared = artifact::execute(shared_request, download_signals::received);
    return Result {
        stage:         local_stage(shared.stage), os_error: shared.os_error, http_status: shared.http_status,
        signal_number: shared.cancellation_reason,
        publication:   if shared.publication == artifact::Publication.Applied { fs::RenameOutcome.Applied }
            else if shared.publication == artifact::Publication.Unknown { fs::RenameOutcome.Unknown }
            else { fs::RenameOutcome.NotAttempted },
        parents_synced:       shared.parents_synced,
        rename_cleanup_error: shared.rename_cleanup_error,
        cleanup_http:         shared.cleanup_http,
        cleanup_file:         shared.cleanup_file,
        cleanup_staging:      shared.cleanup_staging,
        cleanup_root:         shared.cleanup_root,
        cleanup_context:      shared.cleanup_context,
        residue_may_remain:   shared.residue_may_remain,
        received_bytes:       shared.received_bytes,
        written_bytes:        shared.written_bytes,
        ..
    };
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
