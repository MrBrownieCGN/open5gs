/*
 * Copyright (C) 2026 by Daniel Brune <daniel.brune.so@outlook.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Nudm_UEAU GetHssAv (TS 29.503 clause 5.4.2.4).
 *
 * The test plays the HSS: it sends generate-av to the UDM over HTTP/2
 * and checks every vector against Milenage computed here with the
 * K/OPc/AMF of the subscriber, the SQN the UDM has to use, and the RAND
 * returned by the UDM. The SQN written back to the UDR is read from
 * the database.
 */

#include <curl/curl.h>

#include "test-common.h"

#define TEST_UDM_URI "http://127.0.0.12:7777/nudm-ueau/v1"

/* test_db_new_simple(): "amf" 8000, "sqn" 64 */
#define TEST_DB_SQN 64

#define TEST_K "465b5ce8b199b49faa5f0a2ee238a6bc"
#define TEST_OPC "e8ed289deba952e4283b54e88e6183ca"

typedef struct test_http_body_s {
    char *data;
    size_t len;
} test_http_body_t;

static size_t test_http_write(void *ptr, size_t size, size_t nmemb, void *ctx)
{
    test_http_body_t *body = ctx;
    size_t n = size * nmemb;

    body->data = ogs_realloc(body->data, body->len + n + 1);
    ogs_assert(body->data);
    memcpy(body->data + body->len, ptr, n);
    body->len += n;
    body->data[body->len] = 0;

    return n;
}

/* POST a JSON body to the UDM and return the HTTP status (0: no answer) */
static long test_http_post(const char *uri, const char *request,
        cJSON **response, long timeout_sec)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    test_http_body_t body;
    long status = 0;
    CURLcode res;

    memset(&body, 0, sizeof(body));

    curl = curl_easy_init();
    ogs_assert(curl);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    ogs_assert(headers);
    headers = curl_slist_append(headers, "Accept: application/json");
    ogs_assert(headers);

    curl_easy_setopt(curl, CURLOPT_URL, uri);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
            CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, test_http_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    else
        ogs_error("curl_easy_perform() failed [%s]", curl_easy_strerror(res));

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (response)
        *response = body.data ? cJSON_Parse(body.data) : NULL;
    if (body.data)
        ogs_free(body.data);

    return status;
}

/* POST .../{supi}/hss-security-information/{type}/generate-av */
static long test_generate_av_type(const char *supi, const char *type,
        const char *request, cJSON **response, long timeout_sec)
{
    char *uri = NULL;
    long status;

    uri = ogs_msprintf("%s/%s/hss-security-information/%s/generate-av",
            TEST_UDM_URI, supi, type);
    ogs_assert(uri);

    status = test_http_post(uri, request, response, timeout_sec);

    ogs_free(uri);

    return status;
}

static long test_generate_av(const char *supi, const char *type,
        const char *request, cJSON **response)
{
    return test_generate_av_type(supi, type, request, response, 10L);
}

static long test_generate_av_timeout(const char *supi,
        const char *request, cJSON **response, long timeout_sec)
{
    return test_generate_av_type(
            supi, "ims-aka", request, response, timeout_sec);
}

/*
 * 400 of the UDM: the status, and a ProblemDetails body that carries
 * it, so that a bare 400 of the HTTP layer does not pass.
 */
static void test_bad_request(abts_case *tc, long status, cJSON *problem)
{
    cJSON *problem_status = NULL;

    ABTS_INT_EQUAL(tc, 400, (int)status);
    ABTS_PTR_NOTNULL(tc, problem);
    if (!problem)
        return;
    problem_status = cJSON_GetObjectItemCaseSensitive(problem, "status");
    ABTS_TRUE(tc, problem_status && cJSON_IsNumber(problem_status) &&
            problem_status->valueint == 400);
}

/*
 * AUTS = SQN_MS ^ AK* || MAC-S, as the USIM builds it (TS 33.102),
 * for a new random RAND, or for the RAND given in rand_string.
 */
static void test_auts(abts_case *tc, uint64_t ms,
        char *rand_string, char *auts_string)
{
    uint8_t k[OGS_KEY_LEN], opc[OGS_KEY_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t sqn_ms[OGS_SQN_LEN];
    uint8_t amf_star[OGS_AMF_LEN] = { 0x00, 0x00 };
    uint8_t mac_a[8], mac_s[OGS_MAC_S_LEN];
    uint8_t res[OGS_MAX_RES_LEN], ck[OGS_KEY_LEN], ik[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN], ak_star[OGS_AK_LEN];
    uint8_t auts[OGS_AUTS_LEN];
    int i;

    ogs_hex_from_string(TEST_K, k, sizeof(k));
    ogs_hex_from_string(TEST_OPC, opc, sizeof(opc));
    if (rand_string[0])
        ogs_hex_from_string(rand_string, rand, sizeof(rand));
    else
        ogs_random(rand, sizeof(rand));
    ogs_uint64_to_buffer(ms, OGS_SQN_LEN, sqn_ms);

    ABTS_INT_EQUAL(tc, 0, milenage_f1(opc, k, rand, sqn_ms, amf_star,
                mac_a, mac_s));
    ABTS_INT_EQUAL(tc, 0, milenage_f2345(opc, k, rand, res, ck, ik,
                ak, ak_star));
    for (i = 0; i < OGS_SQN_LEN; i++)
        auts[i] = sqn_ms[i] ^ ak_star[i];
    memcpy(auts + OGS_SQN_LEN, mac_s, OGS_MAC_S_LEN);

    ogs_hex_to_ascii(rand, sizeof(rand), rand_string,
            OGS_KEYSTRLEN(OGS_RAND_LEN));
    ogs_hex_to_ascii(auts, sizeof(auts), auts_string,
            OGS_KEYSTRLEN(OGS_AUTS_LEN));
}

static const char *test_cause(cJSON *problem)
{
    cJSON *cause = NULL;

    if (!problem)
        return "";
    cause = cJSON_GetObjectItemCaseSensitive(problem, "cause");
    if (!cause || !cJSON_IsString(cause))
        return "";
    return cause->valuestring;
}

static uint64_t test_db_sqn(const char *supi)
{
    ogs_dbi_auth_info_t auth_info;

    memset(&auth_info, 0, sizeof(auth_info));
    ogs_assert(OGS_OK == ogs_dbi_auth_info((char *)supi, &auth_info));

    return auth_info.sqn;
}

static bool test_hex(cJSON *av, const char *name, uint8_t *out, int len)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(av, name);

    if (!item || !cJSON_IsString(item))
        return false;
    return ogs_hex_from_string_checked(item->valuestring, out, len) == OGS_OK;
}

/*
 * Check one IMS-AKA vector against Milenage(K, OPc, AMF with the
 * separation bit cleared, SQN, RAND of the vector).
 */
static void test_check_vector(abts_case *tc, cJSON *av, uint64_t sqn)
{
    uint8_t k[OGS_KEY_LEN], opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN] = { 0x00, 0x00 }; /* 8000 with bit 0 cleared */
    uint8_t sqn_buf[OGS_SQN_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t xres[8], autn[OGS_AUTN_LEN], ck[OGS_KEY_LEN], ik[OGS_KEY_LEN];
    uint8_t ref_xres[OGS_MAX_RES_LEN], ref_autn[OGS_AUTN_LEN];
    uint8_t ref_ck[OGS_KEY_LEN], ref_ik[OGS_KEY_LEN], ref_ak[OGS_AK_LEN];
    size_t ref_xres_len = sizeof(ref_xres);
    cJSON *av_type = NULL;

    ABTS_PTR_NOTNULL(tc, av);
    if (!av)
        return;

    av_type = cJSON_GetObjectItemCaseSensitive(av, "avType");
    ABTS_TRUE(tc, av_type && cJSON_IsString(av_type) &&
            !strcmp(av_type->valuestring, "IMS_AKA"));

    ABTS_TRUE(tc, test_hex(av, "rand", rand, sizeof(rand)));
    ABTS_TRUE(tc, test_hex(av, "xres", xres, sizeof(xres)));
    ABTS_TRUE(tc, test_hex(av, "autn", autn, sizeof(autn)));
    ABTS_TRUE(tc, test_hex(av, "ck", ck, sizeof(ck)));
    ABTS_TRUE(tc, test_hex(av, "ik", ik, sizeof(ik)));

    ogs_hex_from_string(TEST_K, k, sizeof(k));
    ogs_hex_from_string(TEST_OPC, opc, sizeof(opc));
    ogs_uint64_to_buffer(sqn, OGS_SQN_LEN, sqn_buf);

    milenage_generate(opc, amf, k, sqn_buf, rand,
            ref_autn, ref_ik, ref_ck, ref_ak, ref_xres, &ref_xres_len);

    ABTS_INT_EQUAL(tc, 8, (int)ref_xres_len);
    ABTS_TRUE(tc, memcmp(xres, ref_xres, sizeof(xres)) == 0);
    ABTS_TRUE(tc, memcmp(autn, ref_autn, sizeof(autn)) == 0);
    ABTS_TRUE(tc, memcmp(ck, ref_ck, sizeof(ck)) == 0);
    ABTS_TRUE(tc, memcmp(ik, ref_ik, sizeof(ik)) == 0);

    /* AUTN = SQN^AK || AMF || MAC-A: the separation bit is 0 */
    ABTS_INT_EQUAL(tc, 0, autn[OGS_SQN_LEN] & 0x80);
}

static cJSON *test_vectors(abts_case *tc, cJSON *result, int expected)
{
    cJSON *vectors = NULL;

    ABTS_PTR_NOTNULL(tc, result);
    if (!result)
        return NULL;

    /* TS 29.503 clause 6.3.6.2.12: a plain array of AvImsGbaEapAka */
    vectors = cJSON_GetObjectItemCaseSensitive(
            result, "hssAuthenticationVectors");
    ABTS_TRUE(tc, vectors && cJSON_IsArray(vectors));
    if (!vectors || !cJSON_IsArray(vectors))
        return NULL;

    ABTS_INT_EQUAL(tc, expected, cJSON_GetArraySize(vectors));

    return vectors;
}

static test_ue_t *test_gethssav_ue(abts_case *tc, const char *msin)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;
    bson_t *doc = NULL;

    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    test_ue = test_ue_add_by_suci(&mobile_identity_suci, msin);
    ogs_assert(test_ue);

    test_ue->k_string = TEST_K;
    test_ue->opc_string = TEST_OPC;

    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    return test_ue;
}

/* One vector, then five: contents and SQN handling */
static void test1_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL, *vectors = NULL;
    char *supi = NULL;
    uint64_t sqn;
    long status;
    int i;

    test_ue = test_gethssav_ue(tc, "0000203190");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    /* One vector with the SQN of the UDR */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    vectors = test_vectors(tc, result, 1);
    if (vectors)
        test_check_vector(tc, cJSON_GetArrayItem(vectors, 0), TEST_DB_SQN);
    cJSON_Delete(result);

    /*
     * The UDM writes back the SQN that follows the last vector
     * (64 + 32). The Open5GS UDR adds 32 after the replace.
     */
    sqn = test_db_sqn(supi);
    ABTS_TRUE(tc, sqn > TEST_DB_SQN);
    ABTS_TRUE(tc, sqn == TEST_DB_SQN + 32 + 32);

    /* Five vectors, SQN + 32 * i, all RANDs different */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":5}",
            &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    vectors = test_vectors(tc, result, 5);
    if (vectors) {
        for (i = 0; i < 5; i++)
            test_check_vector(tc,
                    cJSON_GetArrayItem(vectors, i), sqn + 32 * i);
        for (i = 1; i < 5; i++) {
            cJSON *a = cJSON_GetObjectItemCaseSensitive(
                    cJSON_GetArrayItem(vectors, i - 1), "rand");
            cJSON *b = cJSON_GetObjectItemCaseSensitive(
                    cJSON_GetArrayItem(vectors, i), "rand");
            ABTS_TRUE(tc, a && b && strcmp(a->valuestring, b->valuestring));
        }
    }
    cJSON_Delete(result);

    ABTS_TRUE(tc, test_db_sqn(supi) == sqn + 5 * 32 + 32);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/* AUTS re-synchronisation, then a wrong MAC-S */
static void test2_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL, *vectors = NULL;
    char *supi = NULL, *request = NULL;
    char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)] = "";
    char auts_string[OGS_KEYSTRLEN(OGS_AUTS_LEN)];
    size_t last;
    const uint64_t ms = 0x1000;
    uint64_t sqn;
    long status;

    test_ue = test_gethssav_ue(tc, "0000203191");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    test_auts(tc, ms, rand_string, auts_string);

    request = ogs_msprintf("{\"hssAuthType\":\"IMS_AKA\","
            "\"numOfRequestedVectors\":2,"
            "\"resynchronizationInfo\":{\"rand\":\"%s\",\"auts\":\"%s\"}}",
            rand_string, auts_string);
    ogs_assert(request);

    status = test_generate_av(supi, "ims-aka", request, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);

    /* Same rule as the 5G-AKA re-synchronisation: SQN_MS + 32 + 1 */
    sqn = ms + 32 + 1;
    vectors = test_vectors(tc, result, 2);
    if (vectors) {
        test_check_vector(tc, cJSON_GetArrayItem(vectors, 0), sqn);
        test_check_vector(tc, cJSON_GetArrayItem(vectors, 1), sqn + 32);
    }
    cJSON_Delete(result);
    ogs_free(request);

    ABTS_TRUE(tc, test_db_sqn(supi) == sqn + 2 * 32 + 32);

    /* Wrong MAC-S: 403 AUTHENTICATION_REJECTED, SQN unchanged */
    sqn = test_db_sqn(supi);
    last = strlen(auts_string) - 1;
    auts_string[last] = (auts_string[last] == '0') ? '1' : '0';
    request = ogs_msprintf("{\"hssAuthType\":\"IMS_AKA\","
            "\"numOfRequestedVectors\":1,"
            "\"resynchronizationInfo\":{\"rand\":\"%s\",\"auts\":\"%s\"}}",
            rand_string, auts_string);
    ogs_assert(request);

    status = test_generate_av(supi, "ims-aka", request, &result);
    ABTS_INT_EQUAL(tc, 403, (int)status);
    ABTS_STR_EQUAL(tc, "AUTHENTICATION_REJECTED", test_cause(result));
    cJSON_Delete(result);
    ogs_free(request);

    ABTS_TRUE(tc, test_db_sqn(supi) == sqn);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/* Error cases of table 6.3.3.5.4.2.2-2 and of the request */
static void test3_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL;
    char *supi = NULL;
    long status;

    test_ue = test_gethssav_ue(tc, "0000203192");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    /* EPS-AKA is not implemented */
    status = test_generate_av(supi, "eps-aka",
            "{\"hssAuthType\":\"EPS_AKA\",\"numOfRequestedVectors\":1,"
            "\"servingNetworkId\":{\"mcc\":\"999\",\"mnc\":\"70\"}}",
            &result);
    ABTS_INT_EQUAL(tc, 501, (int)status);
    ABTS_STR_EQUAL(tc, "UNSUPPORTED_AUTHENTICATION_METHOD",
            test_cause(result));
    cJSON_Delete(result);

    /* Unknown user */
    status = test_generate_av("imsi-999709999999999", "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    ABTS_INT_EQUAL(tc, 404, (int)status);
    ABTS_STR_EQUAL(tc, "USER_NOT_FOUND", test_cause(result));
    cJSON_Delete(result);

    /* numOfRequestedVectors out of 1..5 */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":6}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":0}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    /* hssAuthType in the body does not match the URI */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"EPS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    /* AUTS of the wrong length */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1,"
            "\"resynchronizationInfo\":{"
            "\"rand\":\"00112233445566778899aabbccddeeff\","
            "\"auts\":\"0011\"}}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    /* AUTS one octet too long */
    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1,"
            "\"resynchronizationInfo\":{"
            "\"rand\":\"00112233445566778899aabbccddeeff\","
            "\"auts\":\"00112233445566778899aabbccddee\"}}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    /* None of the rejected requests has touched the SQN */
    ABTS_TRUE(tc, test_db_sqn(supi) == TEST_DB_SQN);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/* SQN of a vector: AUTN[0..5] = SQN ^ AK, AK = f5(K, RAND) */
static uint64_t test_vector_sqn(cJSON *av)
{
    uint8_t k[OGS_KEY_LEN], opc[OGS_KEY_LEN];
    uint8_t rand[OGS_RAND_LEN], autn[OGS_AUTN_LEN];
    uint8_t res[OGS_MAX_RES_LEN], ck[OGS_KEY_LEN], ik[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN], ak_star[OGS_AK_LEN], sqn[OGS_SQN_LEN];
    int i;

    ogs_hex_from_string(TEST_K, k, sizeof(k));
    ogs_hex_from_string(TEST_OPC, opc, sizeof(opc));
    if (!test_hex(av, "rand", rand, sizeof(rand)) ||
        !test_hex(av, "autn", autn, sizeof(autn)))
        return 0;

    ogs_assert(0 == milenage_f2345(opc, k, rand, res, ck, ik, ak, ak_star));
    for (i = 0; i < OGS_SQN_LEN; i++)
        sqn[i] = autn[i] ^ ak[i];

    return ogs_buffer_to_uint64(sqn, OGS_SQN_LEN);
}

static int test_sqn_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/*
 * Three GetHssAv of the same SUPI at the same time, two vectors each.
 * The UDM serves them one after the other, so the three SQN ranges
 * follow each other: 64/96, 160/192, 256/288 (each request writes back
 * base + 64 and the Open5GS UDR adds 32).
 */
#define TEST_PARALLEL 3
static void test4_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    char *supi = NULL, *uri = NULL;
    CURLM *multi = NULL;
    CURL *curl[TEST_PARALLEL];
    struct curl_slist *headers = NULL;
    test_http_body_t body[TEST_PARALLEL];
    uint64_t sqn[TEST_PARALLEL * 2];
    const uint64_t expected[TEST_PARALLEL * 2] =
        { 64, 96, 160, 192, 256, 288 };
    int running = 0, n = 0, i, j;
    long status;

    test_ue = test_gethssav_ue(tc, "0000203193");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);
    uri = ogs_msprintf("%s/%s/hss-security-information/ims-aka/generate-av",
            TEST_UDM_URI, supi);
    ogs_assert(uri);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    ogs_assert(headers);

    multi = curl_multi_init();
    ogs_assert(multi);

    memset(body, 0, sizeof(body));
    for (i = 0; i < TEST_PARALLEL; i++) {
        curl[i] = curl_easy_init();
        ogs_assert(curl[i]);
        curl_easy_setopt(curl[i], CURLOPT_URL, uri);
        curl_easy_setopt(curl[i], CURLOPT_HTTP_VERSION,
                CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        curl_easy_setopt(curl[i], CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl[i], CURLOPT_POSTFIELDS,
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":2}");
        curl_easy_setopt(curl[i], CURLOPT_WRITEFUNCTION, test_http_write);
        curl_easy_setopt(curl[i], CURLOPT_WRITEDATA, &body[i]);
        curl_easy_setopt(curl[i], CURLOPT_TIMEOUT, 10L);
        curl_multi_add_handle(multi, curl[i]);
    }

    do {
        ogs_assert(CURLM_OK == curl_multi_perform(multi, &running));
        if (running)
            curl_multi_wait(multi, NULL, 0, 100, NULL);
    } while (running);

    for (i = 0; i < TEST_PARALLEL; i++) {
        cJSON *result = NULL, *vectors = NULL;

        status = 0;
        curl_easy_getinfo(curl[i], CURLINFO_RESPONSE_CODE, &status);
        ABTS_INT_EQUAL(tc, 200, (int)status);

        result = body[i].data ? cJSON_Parse(body[i].data) : NULL;
        vectors = test_vectors(tc, result, 2);
        for (j = 0; vectors && j < 2 && n < TEST_PARALLEL * 2; j++) {
            cJSON *av = cJSON_GetArrayItem(vectors, j);
            sqn[n] = test_vector_sqn(av);
            test_check_vector(tc, av, sqn[n]);
            n++;
        }
        cJSON_Delete(result);

        if (body[i].data)
            ogs_free(body[i].data);
        curl_multi_remove_handle(multi, curl[i]);
        curl_easy_cleanup(curl[i]);
    }

    curl_multi_cleanup(multi);
    curl_slist_free_all(headers);

    ABTS_INT_EQUAL(tc, TEST_PARALLEL * 2, n);
    if (n == TEST_PARALLEL * 2) {
        qsort(sqn, n, sizeof(sqn[0]), test_sqn_cmp);
        for (i = 0; i < n; i++)
            ABTS_TRUE(tc, sqn[i] == expected[i]);
    }

    ABTS_TRUE(tc, test_db_sqn(supi) == 352);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(uri);
    ogs_free(supi);
}

/*
 * The consumer gives up on requests while the UDM is still serving them
 * (RST_STREAM). Three requests of the same SUPI are sent at once, so
 * that the second and the third wait behind the first one in the UDM;
 * the streams are reset only after every request has been sent, and
 * before all of them have been answered. The next request of the same
 * SUPI still has to be served, without reusing an SQN.
 */
static void test5_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL, *vectors = NULL;
    char *supi = NULL, *uri = NULL;
    const char *request =
        "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}";
    CURLM *multi = NULL;
    CURL *curl[TEST_PARALLEL];
    struct curl_slist *headers = NULL;
    curl_off_t uploaded;
    CURLMsg *msg = NULL;
    int running, queued, sent, answered = 0;
    uint64_t sqn;
    long status;
    int i, rounds;

    test_ue = test_gethssav_ue(tc, "0000203194");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);
    uri = ogs_msprintf("%s/%s/hss-security-information/ims-aka/generate-av",
            TEST_UDM_URI, supi);
    ogs_assert(uri);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    ogs_assert(headers);

    multi = curl_multi_init();
    ogs_assert(multi);
    curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

    for (i = 0; i < TEST_PARALLEL; i++) {
        curl[i] = curl_easy_init();
        ogs_assert(curl[i]);
        curl_easy_setopt(curl[i], CURLOPT_URL, uri);
        curl_easy_setopt(curl[i], CURLOPT_HTTP_VERSION,
                CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        curl_easy_setopt(curl[i], CURLOPT_PIPEWAIT, 1L);
        curl_easy_setopt(curl[i], CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl[i], CURLOPT_POSTFIELDS, request);
        curl_multi_add_handle(multi, curl[i]);
    }

    /* Drive the transfers until every request body has gone out */
    for (rounds = 0; rounds < 1000; rounds++) {
        curl_multi_perform(multi, &running);
        while ((msg = curl_multi_info_read(multi, &queued)))
            if (msg->msg == CURLMSG_DONE)
                answered++;

        for (sent = 0, i = 0; i < TEST_PARALLEL; i++) {
            uploaded = 0;
            curl_easy_getinfo(curl[i], CURLINFO_SIZE_UPLOAD_T, &uploaded);
            if (uploaded == (curl_off_t)strlen(request))
                sent++;
        }
        if (sent == TEST_PARALLEL || !running)
            break;
        curl_multi_wait(multi, NULL, 0, 1, NULL);
    }
    ABTS_INT_EQUAL(tc, TEST_PARALLEL, sent);

    /* At least one request is still waiting in the UDM: reset them all */
    ABTS_TRUE(tc, answered < TEST_PARALLEL);
    for (i = 0; i < TEST_PARALLEL; i++) {
        curl_multi_remove_handle(multi, curl[i]);
        curl_easy_cleanup(curl[i]);
    }
    curl_multi_cleanup(multi);
    curl_slist_free_all(headers);

    /*
     * The next request is served behind whatever the UDM still does for
     * the reset streams. A reset request whose SQN was stored before
     * the reset moved the SQN on; one that was dropped earlier did not.
     * Either way the vector uses the SQN stored in the UDR, never one
     * below it, and the UDR keeps the SQN after it.
     */
    status = test_generate_av(supi, "ims-aka", request, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    vectors = test_vectors(tc, result, 1);
    if (vectors) {
        sqn = test_vector_sqn(cJSON_GetArrayItem(vectors, 0));
        ABTS_TRUE(tc, sqn >= TEST_DB_SQN);
        test_check_vector(tc, cJSON_GetArrayItem(vectors, 0), sqn);
        ABTS_TRUE(tc, test_db_sqn(supi) == sqn + 32 + 32);
    }
    cJSON_Delete(result);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(uri);
    ogs_free(supi);
}

/*
 * SUPI not in IMSI format, no body: 400. A SUCI is rejected before the
 * UDM tries to de-conceal it, also when its home network key is
 * unknown. An hssAuthType this version does not know is a valid value
 * of the extensible HssAuthTypeInUri that is not supported: 501.
 */
static void test6_func(abts_case *tc, void *data)
{
    cJSON *result = NULL;
    long status;

    status = test_generate_av("suci-0-999-70-0000-1-9-00112233",
            "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    status = test_generate_av("suci-0-999-70-0000-0-0-0000203190",
            "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    test_bad_request(tc, status, result);
    cJSON_Delete(result);

    status = test_generate_av("imsi-999700000203190", "foo-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    ABTS_INT_EQUAL(tc, 501, (int)status);
    ABTS_STR_EQUAL(tc, "UNSUPPORTED_AUTHENTICATION_METHOD",
            test_cause(result));
    cJSON_Delete(result);

    status = test_generate_av("imsi-999700000203190", "ims-aka", "",
            &result);
    ABTS_INT_EQUAL(tc, 400, (int)status);
    cJSON_Delete(result);
}

/*
 * Restart of the UDR (peer restart): the UDR goes away while the HSS
 * keeps asking. The UDM has to answer with an error instead of hanging,
 * the next request of the same SUPI must not wait behind the failed
 * one, and once the UDR is back the vectors continue above the SQN
 * stored before.
 */
static void test7_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL, *vectors = NULL;
    char *supi = NULL;
    const char *request =
        "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}";
    const char *argv[] = { "", "-c", NULL, "-e", "info", NULL };
    uint64_t sqn_before, sqn;
    long status;
    int i;

    test_ue = test_gethssav_ue(tc, "0000203195");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    status = test_generate_av(supi, "ims-aka", request, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    cJSON_Delete(result);
    sqn_before = test_db_sqn(supi);

    test_child_terminate_with_name((char *)"udr", 0);
    ogs_msleep(300);

    /*
     * Answered with a server error: by the SCP, or by the UDM when its
     * CLIENT_WAIT timer towards the UDR expires (10 seconds).
     */
    for (i = 0; i < 2; i++) {
        status = test_generate_av_timeout(supi, request, &result, 15L);
        ABTS_TRUE(tc, status >= 500 && status <= 504);
        cJSON_Delete(result);
    }
    ABTS_TRUE(tc, test_db_sqn(supi) == sqn_before);

    argv[2] = ogs_app()->file;
    ogs_assert(argv[2]);
    test_child_create("udr", 0, argv);

    /* Wait for the UDR to come back (NF registration, discovery) */
    for (i = 0; i < 50; i++) {
        status = test_generate_av(supi, "ims-aka", request, &result);
        if (status == 200)
            break;
        cJSON_Delete(result);
        result = NULL;
        ogs_msleep(200);
    }
    ABTS_INT_EQUAL(tc, 200, (int)status);
    vectors = test_vectors(tc, result, 1);
    if (vectors) {
        sqn = test_vector_sqn(cJSON_GetArrayItem(vectors, 0));
        ABTS_TRUE(tc, sqn == sqn_before);
        test_check_vector(tc, cJSON_GetArrayItem(vectors, 0), sqn);
    }
    cJSON_Delete(result);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/* POST .../{supi}/security-information/generate-auth-data (5G-AKA) */
static long test_generate_auth_data(const char *supi,
        const char *resync, cJSON **response)
{
    char *uri = NULL, *request = NULL;
    long status;

    uri = ogs_msprintf(
            "%s/%s/security-information/generate-auth-data",
            TEST_UDM_URI, supi);
    ogs_assert(uri);
    request = ogs_msprintf("{\"servingNetworkName\":"
            "\"5G:mnc070.mcc999.3gppnetwork.org\","
            "\"ausfInstanceId\":\"4fd1e1f6-6c0a-41f4-a4a9-8b1e1a0c2d3e\"%s}",
            resync ? resync : "");
    ogs_assert(request);

    status = test_http_post(uri, request, response, 10L);

    ogs_free(request);
    ogs_free(uri);

    return status;
}

/*
 * GetHssAv next to a 5G-AKA procedure of the same SUPI: the GetHssAv
 * must neither release the UE context of the 5G-AKA nor overwrite its
 * RAND (the 5G-AKA re-synchronisation compares it), and the 5G-AKA
 * vector keeps the AMF separation bit set (TS 33.501 clause 6.1.3.2).
 */
static void test8_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL, *vector = NULL, *rand = NULL;
    char *supi = NULL, *resync = NULL;
    char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)] = "";
    char auts_string[OGS_KEYSTRLEN(OGS_AUTS_LEN)];
    uint8_t autn[OGS_AUTN_LEN];
    long status;

    test_ue = test_gethssav_ue(tc, "0000203196");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    status = test_generate_auth_data(supi, NULL, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    vector = result ? cJSON_GetObjectItemCaseSensitive(
            result, "authenticationVector") : NULL;
    ABTS_PTR_NOTNULL(tc, vector);
    if (vector) {
        ABTS_TRUE(tc, test_hex(vector, "autn", autn, sizeof(autn)));
        ABTS_INT_EQUAL(tc, 0x80, autn[OGS_SQN_LEN] & 0x80);
        rand = cJSON_GetObjectItemCaseSensitive(vector, "rand");
        ABTS_TRUE(tc, rand && cJSON_IsString(rand) &&
                strlen(rand->valuestring) == sizeof(rand_string) - 1);
        if (rand && cJSON_IsString(rand) &&
                strlen(rand->valuestring) == sizeof(rand_string) - 1)
            memcpy(rand_string, rand->valuestring, sizeof(rand_string));
    }
    cJSON_Delete(result);

    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    test_vectors(tc, result, 1);
    cJSON_Delete(result);

    /* 5G-AKA re-synchronisation against the RAND of the 5G-AKA vector */
    ABTS_TRUE(tc, rand_string[0] != 0);
    test_auts(tc, 0x2000, rand_string, auts_string);
    resync = ogs_msprintf(",\"resynchronizationInfo\":"
            "{\"rand\":\"%s\",\"auts\":\"%s\"}", rand_string, auts_string);
    ogs_assert(resync);

    status = test_generate_auth_data(supi, resync, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    cJSON_Delete(result);
    ogs_free(resync);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/* Keep the Location header of an answer */
static size_t test_http_location(char *ptr, size_t size, size_t nmemb,
        void *ctx)
{
    char **location = ctx;
    size_t n = size * nmemb, s = strlen("location:"), e = n;

    if (!*location && n > s && !ogs_strncasecmp(ptr, "location:", s)) {
        while (s < e && ptr[s] == ' ')
            s++;
        while (e > s && (ptr[e - 1] == '\r' || ptr[e - 1] == '\n'))
            e--;
        *location = ogs_strndup(ptr + s, e - s);
        ogs_assert(*location);
    }

    return n;
}

/* POST or PUT an AuthEvent to the UDM and return the HTTP status */
static long test_http_auth_event(const char *method, const char *uri,
        const char *request, char **location)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    test_http_body_t body;
    long status = 0;

    memset(&body, 0, sizeof(body));

    curl = curl_easy_init();
    ogs_assert(curl);

    headers = curl_slist_append(headers, "Content-Type: application/json");
    ogs_assert(headers);

    curl_easy_setopt(curl, CURLOPT_URL, uri);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
            CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, test_http_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    if (location) {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, test_http_location);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, location);
    }
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (body.data)
        ogs_free(body.data);

    return status;
}

#define TEST_AUTH_EVENT(success, removal) \
    "{\"nfInstanceId\":\"4fd1e1f6-6c0a-41f4-a4a9-8b1e1a0c2d3e\"," \
    "\"success\":" success "," \
    "\"timeStamp\":\"2026-11-04T12:00:00Z\",\"authType\":\"5G_AKA\"," \
    "\"servingNetworkName\":\"5G:mnc070.mcc999.3gppnetwork.org\"" \
    removal "}"

/*
 * The AUSF removes the result of a 5G-AKA (PUT on the auth-events
 * resource it got from the UDM) after a GetHssAv of the same SUPI. The
 * UE context that holds the AuthEvent must still be there, otherwise
 * the UDM answers 404 to the removal.
 */
static void test9_func(abts_case *tc, void *data)
{
    test_ue_t *test_ue = NULL;
    cJSON *result = NULL;
    char *supi = NULL, *uri = NULL, *location = NULL;
    long status;

    test_ue = test_gethssav_ue(tc, "0000203197");
    supi = ogs_msprintf("imsi-%s", test_ue->imsi);
    ogs_assert(supi);

    status = test_generate_auth_data(supi, NULL, &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    cJSON_Delete(result);

    uri = ogs_msprintf("%s/%s/auth-events", TEST_UDM_URI, supi);
    ogs_assert(uri);
    status = test_http_auth_event("POST", uri,
            TEST_AUTH_EVENT("true", ""), &location);
    ABTS_INT_EQUAL(tc, 201, (int)status);
    ABTS_PTR_NOTNULL(tc, location);
    ogs_free(uri);

    status = test_generate_av(supi, "ims-aka",
            "{\"hssAuthType\":\"IMS_AKA\",\"numOfRequestedVectors\":1}",
            &result);
    ABTS_INT_EQUAL(tc, 200, (int)status);
    test_vectors(tc, result, 1);
    cJSON_Delete(result);

    if (location) {
        status = test_http_auth_event("PUT", location,
                TEST_AUTH_EVENT("false", ",\"authRemovalInd\":true"), NULL);
        ABTS_INT_EQUAL(tc, 204, (int)status);
        ogs_free(location);
    }

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    test_ue_remove(test_ue);
    ogs_free(supi);
}

/*
 * The HSS finds the UDM through the NRF: NF discovery with
 * requester-nf-type=HSS for nudm-ueau returns the UDM, which lists the
 * HSS among the NF types allowed to use the UDM and nudm-ueau.
 */
static void test10_func(abts_case *tc, void *data)
{
    CURL *curl = NULL;
    test_http_body_t body;
    cJSON *result = NULL, *instances = NULL, *instance = NULL, *type = NULL;
    long status = 0;
    bool found = false;

    memset(&body, 0, sizeof(body));

    curl = curl_easy_init();
    ogs_assert(curl);

    curl_easy_setopt(curl, CURLOPT_URL,
            "http://127.0.0.10:7777/nnrf-disc/v1/nf-instances"
            "?target-nf-type=UDM&requester-nf-type=HSS"
            "&service-names=nudm-ueau");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
            CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, test_http_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    if (curl_easy_perform(curl) == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);

    ABTS_INT_EQUAL(tc, 200, (int)status);
    result = body.data ? cJSON_Parse(body.data) : NULL;
    if (body.data)
        ogs_free(body.data);

    instances = result ?
        cJSON_GetObjectItemCaseSensitive(result, "nfInstances") : NULL;
    if (instances && cJSON_IsArray(instances)) {
        cJSON_ArrayForEach(instance, instances) {
            type = cJSON_GetObjectItemCaseSensitive(instance, "nfType");
            if (type && cJSON_IsString(type) &&
                    !strcmp(type->valuestring, "UDM"))
                found = true;
        }
    }
    ABTS_TRUE(tc, found);
    cJSON_Delete(result);
}

abts_suite *test_gethssav(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);
    abts_run_test(suite, test2_func, NULL);
    abts_run_test(suite, test3_func, NULL);
    abts_run_test(suite, test4_func, NULL);
    abts_run_test(suite, test5_func, NULL);
    abts_run_test(suite, test6_func, NULL);
    abts_run_test(suite, test7_func, NULL);
    abts_run_test(suite, test8_func, NULL);
    abts_run_test(suite, test9_func, NULL);
    abts_run_test(suite, test10_func, NULL);

    return suite;
}
