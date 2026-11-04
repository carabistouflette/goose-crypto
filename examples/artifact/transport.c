/* SPDX-License-Identifier: Apache-2.0 */
/* Test binary only: trust a fixture CA without weakening certificate verification. */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
CURLcode __real_curl_easy_perform(CURL *handle);
CURLcode __wrap_curl_easy_perform(CURL *handle) {
    const char *expected = getenv("GOOSE_ARTIFACT_FIXTURE_URL");
    const char *ca = getenv("GOOSE_ARTIFACT_FIXTURE_CA");
    char *actual = NULL;
    if (!expected || !ca || strncmp(expected, "https://localhost:", 18) != 0 ||
        curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &actual) != CURLE_OK ||
        !actual || strcmp(actual, expected) != 0) {
        fputs("artifact fixture rejected unexpected URL\n", stderr); exit(90);
    }
    if (curl_easy_setopt(handle, CURLOPT_CAINFO, ca) != CURLE_OK) {
        fputs("artifact fixture CA setup failed\n", stderr); exit(90);
    }
    return __real_curl_easy_perform(handle);
}
