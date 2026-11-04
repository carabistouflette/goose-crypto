/* SPDX-License-Identifier: Apache-2.0 */
/* Fixture only: trust one local CA without weakening TLS verification. */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
CURLMcode __real_curl_multi_add_handle(CURLM *, CURL *);
CURLMcode __wrap_curl_multi_add_handle(CURLM *multi, CURL *easy) {
    const char *expected = getenv("GOOSE_DOWNLOAD_FIXTURE_URL");
    const char *ca = getenv("GOOSE_DOWNLOAD_FIXTURE_CA");
    char *actual = NULL;
    if (!expected || !ca || strncmp(expected, "https://localhost:", 18) != 0 ||
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &actual) != CURLE_OK ||
        !actual || strcmp(actual, expected) != 0) {
        fputs("download fixture rejected unexpected URL\n", stderr); exit(90);
    }
    if (curl_easy_setopt(easy, CURLOPT_CAINFO, ca) != CURLE_OK) {
        fputs("download fixture CA setup failed\n", stderr); exit(90);
    }
    return __real_curl_multi_add_handle(multi, easy);
}
CURLMcode __real_curl_multi_cleanup(CURLM *multi);
CURLMcode __wrap_curl_multi_cleanup(CURLM *multi) {
    CURLMcode result = __real_curl_multi_cleanup(multi);
    const char *fault = getenv("GOOSE_DOWNLOAD_FAULT");
    if (result == CURLM_OK && fault && strcmp(fault, "http-multi-cleanup") == 0) return CURLM_INTERNAL_ERROR;
    return result;
}
