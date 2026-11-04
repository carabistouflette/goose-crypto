// SPDX-License-Identifier: Apache-2.0
namespace download_signals;
// Process-global foreground CLI guard. Call stop even after a failed start.
extern fn start() -> i64 = "gd_signals_start";
extern fn received() -> i64 = "gd_signals_received";
extern fn stop() -> i64 = "gd_signals_stop";
