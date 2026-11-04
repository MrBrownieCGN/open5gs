/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "nudr-handler.h"
#include "nudm-handler.h"
#include "sbi-path.h"

bool udm_nudr_dr_handle_subscription_authentication(
    udm_ue_t *udm_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

#if 0
#if 0
    const char *tmp[1] = { "de8ca9df474091fe4e9263c5daa907e9" };
    /* PFCP test */
    const char *tmp[1] = { "cc3766b98a8031a7286a68c7f577ed2e" };
#endif
    /* Xn-Handover */
    const char *tmp[1] = { "5ca0df8c9bb8dbcf3c2a7dd448da1369" };

#if 0
    /* ISSUE-482 */
    const char *tmp[2] = {
        "3a1fa0f51fe50f324f8522b220fc62a2",
        "cc5539bf72824c879e47e73efc885021"
    };
#endif
    static int step = 0;
#endif

    uint8_t autn[OGS_AUTN_LEN];
    uint8_t ik[OGS_KEY_LEN];
    uint8_t ck[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    size_t xres_len = 8;
    uint8_t xres_star[OGS_MAX_RES_LEN];
    uint8_t kausf[OGS_SHA256_DIGEST_SIZE];

    char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)];
    char autn_string[OGS_KEYSTRLEN(OGS_AUTN_LEN)];
    char kausf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];
    char xres_star_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    OpenAPI_authentication_subscription_t *AuthenticationSubscription = NULL;
    OpenAPI_authentication_info_result_t AuthenticationInfoResult;
    OpenAPI_authentication_vector_t AuthenticationVector;

    ogs_assert(udm_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_SUBSCRIPTION)
        SWITCH(recvmsg->h.method)
        CASE(OGS_SBI_HTTP_METHOD_GET)
            if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_OK) {
                strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                        udm_ue->suci, recvmsg->res_status);
                ogs_assert(strerror);

                if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_NOT_FOUND)
                    ogs_warn("%s", strerror);
                else
                    ogs_error("%s", strerror);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, recvmsg->res_status, recvmsg, strerror, NULL,
                        (recvmsg->ProblemDetails) ?
                                recvmsg->ProblemDetails->cause : NULL));
                ogs_free(strerror);
                return false;
            }

            AuthenticationSubscription = recvmsg->AuthenticationSubscription;
            if (!AuthenticationSubscription) {
                ogs_error("[%s] No AuthenticationSubscription", udm_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                        recvmsg, "No AuthenticationSubscription",
                        udm_ue->suci, NULL));
                return false;
            }

            if (AuthenticationSubscription->authentication_method !=
                    OpenAPI_auth_method_5G_AKA) {
                ogs_error("[%s] Not supported Auth Method [%d]",
                        udm_ue->suci,
                        AuthenticationSubscription->authentication_method);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_FORBIDDEN,
                        recvmsg, "Not supported Auth Method", udm_ue->suci,
                        NULL));
                return false;

            }

            if (!AuthenticationSubscription->enc_permanent_key) {
                ogs_error("[%s] No encPermanentKey", udm_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                        recvmsg, "No encPermanentKey", udm_ue->suci,
                        NULL));
                return false;
            }
            if (!AuthenticationSubscription->enc_opc_key) {
                ogs_error("[%s] No encPermanentKey", udm_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No encPermanentKey", udm_ue->suci, NULL));
                return false;
            }
            if (!AuthenticationSubscription->authentication_management_field) {
                ogs_error("[%s] No authenticationManagementField",
                        udm_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No authenticationManagementField", udm_ue->suci,
                    NULL));
            return false;
        }
        if (!AuthenticationSubscription->sequence_number) {
            ogs_error("[%s] No SequenceNumber", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No SequenceNumber", udm_ue->suci, NULL));
                return false;
            }
            if (!AuthenticationSubscription->sequence_number->sqn) {
                ogs_error("[%s] No SequenceNumber.sqn", udm_ue->suci);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "No SequenceNumber.sqn", udm_ue->suci, NULL));
                return false;
            }

            udm_ue->auth_type = OpenAPI_auth_type_5G_AKA;

            ogs_ascii_to_hex(
                AuthenticationSubscription->enc_opc_key,
                strlen(AuthenticationSubscription->enc_opc_key),
                udm_ue->opc, sizeof(udm_ue->opc));
            ogs_ascii_to_hex(
                AuthenticationSubscription->authentication_management_field,
                strlen(AuthenticationSubscription->
                    authentication_management_field),
                udm_ue->amf, sizeof(udm_ue->amf));
            ogs_ascii_to_hex(
                AuthenticationSubscription->enc_permanent_key,
                strlen(AuthenticationSubscription->enc_permanent_key),
                udm_ue->k, sizeof(udm_ue->k));
            ogs_ascii_to_hex(
                AuthenticationSubscription->sequence_number->sqn,
                strlen(AuthenticationSubscription->sequence_number->sqn),
                udm_ue->sqn, sizeof(udm_ue->sqn));

        CASE(OGS_SBI_HTTP_METHOD_PATCH)
            if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_OK &&
                recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                        udm_ue->suci, recvmsg->res_status);
                ogs_assert(strerror);

                ogs_error("%s", strerror);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, recvmsg->res_status, recvmsg, strerror, NULL,
                        (recvmsg->ProblemDetails) ?
                                recvmsg->ProblemDetails->cause : NULL));
                ogs_free(strerror);
                return false;
            }

            memset(&AuthenticationInfoResult,
                    0, sizeof(AuthenticationInfoResult));

            AuthenticationInfoResult.supi = udm_ue->supi;
            if (!udm_ue->auth_type)
                udm_ue->auth_type = OpenAPI_auth_type_5G_AKA;
            AuthenticationInfoResult.auth_type = udm_ue->auth_type;

            ogs_random(udm_ue->rand, OGS_RAND_LEN);
#if 0
            OGS_HEX(tmp[step], strlen(tmp[step]), udm_ue->rand);
#if 0
            if (step == 0) step = 1; /* For supporting authentication failure */
            else step = 0;
#endif
#endif

            milenage_generate(udm_ue->opc, udm_ue->amf, udm_ue->k, udm_ue->sqn,
                    udm_ue->rand, autn, ik, ck, ak, xres, &xres_len);

            ogs_assert(udm_ue->serving_network_name);

            /* TS33.501 Annex A.2 : Kausf derviation function */
            ogs_kdf_kausf(
                    ck, ik,
                    udm_ue->serving_network_name, autn,
                    kausf);

            /* TS33.501 Annex A.4 : RES* and XRES* derivation function */
            ogs_kdf_xres_star(
                    ck, ik,
                    udm_ue->serving_network_name, udm_ue->rand, xres, xres_len,
                    xres_star);

            memset(&AuthenticationVector, 0, sizeof(AuthenticationVector));
            AuthenticationVector.av_type = OpenAPI_av_type_5G_HE_AKA;

            ogs_hex_to_ascii(udm_ue->rand, sizeof(udm_ue->rand),
                    rand_string, sizeof(rand_string));
            AuthenticationVector.rand = rand_string;
            ogs_hex_to_ascii(xres_star, sizeof(xres_star),
                    xres_star_string, sizeof(xres_star_string));
            AuthenticationVector.xres_star = xres_star_string;
            ogs_hex_to_ascii(autn, sizeof(autn),
                    autn_string, sizeof(autn_string));
            AuthenticationVector.autn = autn_string;
            ogs_hex_to_ascii(kausf, sizeof(kausf),
                    kausf_string, sizeof(kausf_string));
            AuthenticationVector.kausf = kausf_string;

            AuthenticationInfoResult.authentication_vector =
                &AuthenticationVector;

            memset(&sendmsg, 0, sizeof(sendmsg));

            ogs_assert(AuthenticationInfoResult.auth_type);
            sendmsg.AuthenticationInfoResult = &AuthenticationInfoResult;

            response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

            break;

        DEFAULT
            ogs_error("Invalid HTTP method [%s]", recvmsg->h.method);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                    "Invalid HTTP method", recvmsg->h.method, NULL));
            return false;
        END
        break;

    CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_STATUS)
        OpenAPI_auth_event_t *AuthEvent = NULL;

        if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
            strerror = ogs_msprintf("[%s] HTTP response error [%d]",
                    udm_ue->suci, recvmsg->res_status);
            ogs_assert(strerror);

            ogs_error("%s", strerror);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, recvmsg->res_status, recvmsg, strerror, NULL,
                    (recvmsg->ProblemDetails) ?
                            recvmsg->ProblemDetails->cause : NULL));
            ogs_free(strerror);
            return false;
        }

        AuthEvent = udm_ue->auth_event;
        if (!AuthEvent) {
            ogs_error("[%s] No AuthEvent", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AuthEvent", udm_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->nf_instance_id) {
            ogs_error("[%s] No nfInstanceId", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No nfInstanceId", udm_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->time_stamp) {
            ogs_error("[%s] No timeStamp", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No timeStamp", udm_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->auth_type) {
            ogs_error("[%s] No authType", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No authType", udm_ue->suci, NULL));
            return false;
        }

        if (!AuthEvent->serving_network_name) {
            ogs_error("[%s] No servingNetworkName", udm_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No servingNetworkName", udm_ue->suci, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        if (AuthEvent->auth_removal_ind) {
            OpenAPI_auth_event_free(AuthEvent);
            udm_ue->auth_event = NULL;
            response = ogs_sbi_build_response(&sendmsg,
                    OGS_SBI_HTTP_STATUS_NO_CONTENT);
        } else {
            memset(&header, 0, sizeof(header));
            header.service.name =
                OpenAPI_service_name_ToString(OpenAPI_service_name_nudm_ueau);
            header.api.version = (char *)OGS_SBI_API_V1;
            header.resource.component[0] = udm_ue->supi;
            header.resource.component[1] =
                (char *)OGS_SBI_RESOURCE_NAME_AUTH_EVENTS;
            header.resource.component[2] = udm_ue->ctx_id;

            sendmsg.http.location = ogs_sbi_server_uri(server, &header);
            sendmsg.AuthEvent = OpenAPI_auth_event_copy(
                    sendmsg.AuthEvent, udm_ue->auth_event);

            response = ogs_sbi_build_response(&sendmsg,
                    OGS_SBI_HTTP_STATUS_CREATED);
        }
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);
        OpenAPI_auth_event_free(sendmsg.AuthEvent);
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                udm_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

/*
 * GetHssAv: an error of the UDR is not an error of the request of the
 * consumer. 5xx of the UDR are passed on, anything else becomes 500.
 */
static void hss_av_send_udr_error(udm_ue_t *udm_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int status = recvmsg->res_status;

    ogs_error("[%s] HTTP response error from UDR [%d]",
            udm_ue->supi, recvmsg->res_status);

    if (status < OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR)
        status = OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;

    ogs_assert(true ==
        ogs_sbi_server_send_error(stream, status, recvmsg,
            "HTTP response error from UDR", udm_ue->supi,
            (recvmsg->ProblemDetails) ?
                    recvmsg->ProblemDetails->cause : NULL));
}

/*
 * GetHssAv: take K, OPc, AMF and the SQN of the subscription into the
 * request. Returns NULL, or the name of the attribute that is missing
 * or malformed; the UDR handed out data that cannot be used, which is
 * an internal error of the UDM (500), not one of the consumer.
 */
static const char *hss_av_take_credentials(udm_hss_av_request_t *request,
        OpenAPI_authentication_subscription_t *AuthenticationSubscription)
{
    uint8_t sqn[OGS_SQN_LEN];

    ogs_assert(request);
    ogs_assert(AuthenticationSubscription);

    if (ogs_hex_from_string_checked(
                AuthenticationSubscription->enc_permanent_key,
                request->k, sizeof(request->k)) != OGS_OK)
        return "encPermanentKey";
    if (ogs_hex_from_string_checked(
                AuthenticationSubscription->enc_opc_key,
                request->opc, sizeof(request->opc)) != OGS_OK)
        return "encOpcKey";
    if (ogs_hex_from_string_checked(
                AuthenticationSubscription->authentication_management_field,
                request->amf, sizeof(request->amf)) != OGS_OK)
        return "authenticationManagementField";
    if (!AuthenticationSubscription->sequence_number ||
        ogs_hex_from_string_checked(
                AuthenticationSubscription->sequence_number->sqn,
                sqn, sizeof(sqn)) != OGS_OK)
        return "sequenceNumber.sqn";

    request->first_sqn = ogs_buffer_to_uint64(sqn, OGS_SQN_LEN);

    return NULL;
}

/*
 * GetHssAv (TS 29.503 clause 5.4.2.4), answer from the UDR to the GET of
 * the authentication subscription: check the credentials, settle the
 * SQN of the first vector (with AUTS re-synchronisation if requested)
 * and write the SQN that follows the last vector back to the UDR.
 *
 * The SQN is stored before any vector leaves the UDM. If the UDR
 * cannot store it, no vector is returned, so a GetHssAv never hands
 * out an SQN twice. This holds against the other GetHssAv of the same
 * SUPI in this UDM (they are serialised, see udm_hss_av_request_t); it
 * does not cover the 5G-AKA procedure, the Cx MAR of the Open5GS HSS,
 * or other UDM instances, which read and write the same SQN without a
 * common lock.
 */
static bool hss_av_handle_authentication_subscription(
        udm_ue_t *udm_ue, udm_hss_av_request_t *request,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_subscription_t *AuthenticationSubscription;
    const char *invalid = NULL;
    uint8_t next_sqn_buf[OGS_SQN_LEN];
    uint8_t sqn_ms[OGS_SQN_LEN];
    uint8_t mac_s[OGS_MAC_S_LEN];
    uint64_t next_sqn;
    int r;

    ogs_assert(udm_ue);
    ogs_assert(request);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    switch (recvmsg->res_status) {
    case OGS_SBI_HTTP_STATUS_OK:
        break;
    case OGS_SBI_HTTP_STATUS_NOT_FOUND:
        /* Figure 5.4.2.4.2-1 step 2c */
        ogs_warn("[%s] User not found", udm_ue->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND, recvmsg,
                "User not found", udm_ue->supi,
                OGS_SBI_APP_STRERROR_USER_NOT_FOUND));
        return false;
    default:
        hss_av_send_udr_error(udm_ue, stream, recvmsg);
        return false;
    }

    AuthenticationSubscription = recvmsg->AuthenticationSubscription;
    if (!AuthenticationSubscription) {
        ogs_error("[%s] No AuthenticationSubscription", udm_ue->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, recvmsg,
                "No AuthenticationSubscription", udm_ue->supi, NULL));
        return false;
    }

    /*
     * IMS-AKA runs the AKA functions on the permanent key K and OPc of
     * the subscription; an authentication method without them cannot
     * give IMS-AKA vectors (figure 5.4.2.4.2-1 step 2b). 5G-AKA and
     * EAP-AKA' subscriptions both carry K and OPc in the
     * AuthenticationSubscription of the UDR.
     */
    switch (AuthenticationSubscription->authentication_method) {
    case OpenAPI_auth_method_5G_AKA:
    case OpenAPI_auth_method_EAP_AKA_PRIME:
        break;
    default:
        ogs_error("[%s] No AKA subscription [%s]", udm_ue->supi,
                OpenAPI_auth_method_ToString(
                    AuthenticationSubscription->authentication_method));
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                "No AKA subscription", udm_ue->supi,
                OGS_SBI_APP_STRERROR_AUTHENTICATION_REJECTED));
        return false;
    }

    invalid = hss_av_take_credentials(request, AuthenticationSubscription);
    if (invalid) {
        ogs_error("[%s] Invalid %s", udm_ue->supi, invalid);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR, recvmsg,
                "Invalid authentication subscription", invalid, NULL));
        return false;
    }

    if (request->resync_requested) {
        /*
         * TS 33.203 clause 6.1.0: "The requirements on the handling of
         * the counters and mechanisms for sequence number management are
         * specified in TS 33.102". MAC-S authenticates SQN_MS against
         * the RAND given by the consumer, so no RAND has to be kept in
         * the UDM between two GetHssAv requests.
         */
        ogs_auc_sqn(request->opc, request->k,
                request->resync_rand, request->resync_auts, sqn_ms, mac_s);
        if (memcmp(request->resync_auts + OGS_SQN_LEN,
                    mac_s, OGS_MAC_S_LEN) != 0) {
            ogs_error("[%s] Re-synch MAC failed", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                    "Re-sync MAC failed", udm_ue->supi,
                    OGS_SBI_APP_STRERROR_AUTHENTICATION_REJECTED));
            return false;
        }

        /*
         * Same SQN after re-synchronisation as the 5G-AKA path in
         * udm_nudm_ueau_handle_get(): SQN_MS + 32 + 1.
         */
        request->first_sqn = (ogs_buffer_to_uint64(sqn_ms, OGS_SQN_LEN) +
                32 + 1) & OGS_MAX_SQN;
    }

    /*
     * Vector i uses SQN + 32 * i, the step of the 5G-AKA path. The UDR
     * is told the SQN that follows the last vector, i.e. the next SQN
     * that may be used. A UDR that stores the value as given, and the
     * Open5GS UDR that adds another 32 after the replace, both keep the
     * SQN in the UDR above every SQN handed out here.
     */
    next_sqn = (request->first_sqn +
            32 * (uint64_t)request->num_of_requested_vectors) & OGS_MAX_SQN;
    ogs_uint64_to_buffer(next_sqn, OGS_SQN_LEN, next_sqn_buf);

    r = udm_ue_sbi_discover_and_send(OpenAPI_service_name_nudr_dr, NULL,
            udm_nudr_dr_build_authentication_subscription,
            udm_ue, NULL, UDM_SBI_UE_HSS_AV, next_sqn_buf);
    if (r != OGS_OK) {
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT, recvmsg,
                "Cannot store SQN in UDR", udm_ue->supi, NULL));
        return false;
    }

    return true;
}

/*
 * GetHssAv, answer from the UDR to the PATCH of the SQN: build the
 * IMS-AKA vectors and return them to the consumer.
 */
static void hss_av_send_vectors(
        udm_ue_t *udm_ue, udm_hss_av_request_t *request,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    OpenAPI_hss_authentication_info_result_t *HssAuthenticationInfoResult;
    OpenAPI_list_t *AvList = NULL;
    OpenAPI_av_ims_gba_eap_aka_t *Av = NULL;

    uint8_t amf[OGS_AMF_LEN];
    uint8_t sqn[OGS_SQN_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t autn[OGS_AUTN_LEN];
    uint8_t ik[OGS_KEY_LEN];
    uint8_t ck[OGS_KEY_LEN];
    uint8_t ak[OGS_AK_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    size_t xres_len;

    char rand_string[OGS_KEYSTRLEN(OGS_RAND_LEN)];
    char xres_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];
    char autn_string[OGS_KEYSTRLEN(OGS_AUTN_LEN)];
    char ck_string[OGS_KEYSTRLEN(OGS_KEY_LEN)];
    char ik_string[OGS_KEYSTRLEN(OGS_KEY_LEN)];

    int i;

    ogs_assert(udm_ue);
    ogs_assert(request);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    switch (recvmsg->res_status) {
    case OGS_SBI_HTTP_STATUS_OK:
    case OGS_SBI_HTTP_STATUS_NO_CONTENT:
        break;
    case OGS_SBI_HTTP_STATUS_NOT_FOUND:
        /* The subscriber was removed between GET and PATCH */
        ogs_warn("[%s] User not found", udm_ue->supi);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_FOUND, recvmsg,
                "User not found", udm_ue->supi,
                OGS_SBI_APP_STRERROR_USER_NOT_FOUND));
        return;
    default:
        hss_av_send_udr_error(udm_ue, stream, recvmsg);
        return;
    }

    /*
     * AMF separation bit cleared: "bit 0 of the AMF field of AUTN"
     * (TS 33.401 clause 6.1.1), i.e. the most significant bit of amf[0].
     *
     * TS 33.401 clause 6.1.2: "if the "separation bit" is set to 0, the
     * vector is usable in a non-EPS context only (e.g. GSM, UMTS). For
     * authentication vectors with the "separation bit" set to 1, the
     * secret keys CK and IK generated during AKA shall never leave the
     * HSS." TS 33.501 clause 6.1.3.2 sets the bit for 5G-AKA in the same
     * way. An IMS-AKA vector hands CK and IK to the S-CSCF
     * (TS 33.203 clause 6.1.1), so the bit is cleared here.
     *
     * The 5G-AKA path and the Cx MAR of the Open5GS HSS use the AMF
     * of the subscription as it is stored (8000 by default) and are
     * not changed here.
     */
    memcpy(amf, request->amf, sizeof(amf));
    amf[0] &= 0x7f;

    AvList = OpenAPI_list_create();
    ogs_assert(AvList);

    for (i = 0; i < request->num_of_requested_vectors; i++) {
        ogs_uint64_to_buffer(
                (request->first_sqn + 32 * (uint64_t)i) & OGS_MAX_SQN,
                OGS_SQN_LEN, sqn);
        ogs_random(rand, sizeof(rand));

        xres_len = sizeof(xres);
        milenage_generate(request->opc, amf, request->k, sqn, rand,
                autn, ik, ck, ak, xres, &xres_len);

        ogs_hex_to_ascii(rand, sizeof(rand),
                rand_string, sizeof(rand_string));
        ogs_hex_to_ascii(xres, xres_len,
                xres_string, sizeof(xres_string));
        ogs_hex_to_ascii(autn, sizeof(autn),
                autn_string, sizeof(autn_string));
        ogs_hex_to_ascii(ck, sizeof(ck), ck_string, sizeof(ck_string));
        ogs_hex_to_ascii(ik, sizeof(ik), ik_string, sizeof(ik_string));

        Av = OpenAPI_av_ims_gba_eap_aka_create(
                OpenAPI_hss_av_type_IMS_AKA,
                ogs_strdup(rand_string), ogs_strdup(xres_string),
                ogs_strdup(autn_string), ogs_strdup(ck_string),
                ogs_strdup(ik_string));
        ogs_assert(Av);
        ogs_assert(Av->rand && Av->xres && Av->autn && Av->ck && Av->ik);

        OpenAPI_list_add(AvList, Av);
    }

    /*
     * The stack copies of CK and IK are cleared; the copies in the
     * response model are released with it, as in the 5G-AKA path.
     */
    memset(ck, 0, sizeof(ck));
    memset(ik, 0, sizeof(ik));
    memset(ck_string, 0, sizeof(ck_string));
    memset(ik_string, 0, sizeof(ik_string));

    HssAuthenticationInfoResult = OpenAPI_hss_authentication_info_result_create(
            NULL, OpenAPI_hss_authentication_vectors_create(
                NULL, AvList, NULL));
    ogs_assert(HssAuthenticationInfoResult);
    ogs_assert(HssAuthenticationInfoResult->hss_authentication_vectors);

    memset(&sendmsg, 0, sizeof(sendmsg));
    sendmsg.HssAuthenticationInfoResult = HssAuthenticationInfoResult;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    OpenAPI_hss_authentication_info_result_free(HssAuthenticationInfoResult);
}

void udm_nudr_dr_handle_hss_authentication(
    udm_ue_t *udm_ue, ogs_sbi_message_t *recvmsg)
{
    udm_hss_av_request_t *request = NULL;
    ogs_sbi_stream_t *stream = NULL;

    ogs_assert(udm_ue);
    ogs_assert(recvmsg);

    /*
     * Only the head of the list has a transaction towards the UDR, and
     * it is released only after this answer or the CLIENT_WAIT timer.
     */
    request = udm_hss_av_request_head(udm_ue);
    ogs_assert(request);

    stream = ogs_sbi_stream_find_by_id(request->stream_id);
    if (!stream) {
        /*
         * The consumer has gone. After a GET nothing is written; after
         * a PATCH the SQN has moved on and the vectors are not built,
         * which leaves a gap but never reuses an SQN.
         */
        ogs_warn("[%s] GetHssAv consumer has gone [%d]",
                udm_ue->supi, request->stream_id);
        udm_nudm_ueau_hss_av_finish_head(udm_ue);
        return;
    }

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_AUTHENTICATION_SUBSCRIPTION)
        SWITCH(recvmsg->h.method)
        CASE(OGS_SBI_HTTP_METHOD_GET)
            if (hss_av_handle_authentication_subscription(
                        udm_ue, request, stream, recvmsg) == true)
                return; /* waiting for the PATCH */
            break;
        CASE(OGS_SBI_HTTP_METHOD_PATCH)
            hss_av_send_vectors(udm_ue, request, stream, recvmsg);
            break;
        DEFAULT
            ogs_error("[%s] Invalid HTTP method [%s]",
                    udm_ue->supi, recvmsg->h.method);
            ogs_assert_if_reached();
        END
        break;

    DEFAULT
        ogs_error("[%s] Invalid resource name [%s]",
                udm_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert_if_reached();
    END

    udm_nudm_ueau_hss_av_finish_head(udm_ue);
}

bool udm_nudr_dr_handle_subscription_context(
    udm_ue_t *udm_ue, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    int status;

    ogs_assert(udm_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
        ogs_error("[%s] HTTP response error [%d]",
            udm_ue->supi, recvmsg->res_status);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, recvmsg->res_status,
                NULL, "HTTP response error", udm_ue->supi,
                (recvmsg->ProblemDetails) ?
                        recvmsg->ProblemDetails->cause : NULL));
        return false;
    }

    SWITCH(recvmsg->h.method)
    CASE(OGS_SBI_HTTP_METHOD_PATCH)
        SWITCH(recvmsg->h.resource.component[3])
        CASE(OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS)
            memset(&sendmsg, 0, sizeof(sendmsg));

            response = ogs_sbi_build_response(
                    &sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
            return true;

        DEFAULT
            strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                    udm_ue->supi, recvmsg->h.resource.component[3]);
            ogs_assert(strerror);

            ogs_error("%s", strerror);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, strerror, NULL, NULL));
            ogs_free(strerror);
            return false;
        END
    END

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS)
        OpenAPI_amf3_gpp_access_registration_t
            *Amf3GppAccessRegistration = NULL;
        OpenAPI_guami_t *Guami = NULL;

        Amf3GppAccessRegistration = udm_ue->amf_3gpp_access_registration;

        if (!Amf3GppAccessRegistration) {
            ogs_error("[%s] No Amf3GppAccessRegistration", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Amf3GppAccessRegistration", udm_ue->supi,
                    NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->amf_instance_id) {
            ogs_error("[%s] No amfInstanceId", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No amfInstanceId", udm_ue->supi, NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->dereg_callback_uri) {
            ogs_error("[%s] No dregCallbackUri", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No dregCallbackUri", udm_ue->supi, NULL));
            return false;
        }

        Guami = Amf3GppAccessRegistration->guami;
        if (!Guami) {
            ogs_error("[%s] No Guami", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Guami", udm_ue->supi, NULL));
            return false;
        }

        if (!Guami->amf_id) {
            ogs_error("[%s] No Guami.AmfId", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Guami.AmfId", udm_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id) {
            ogs_error("[%s] No PlmnId", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId", udm_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id->mnc) {
            ogs_error("[%s] No PlmnId.Mnc", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId.Mnc", udm_ue->supi, NULL));
            return false;
        }

        if (!Guami->plmn_id->mcc) {
            ogs_error("[%s] No PlmnId.Mcc", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No PlmnId.Mcc", udm_ue->supi, NULL));
            return false;
        }

        if (!Amf3GppAccessRegistration->rat_type) {
            ogs_error("[%s] No RatType", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No RatType", udm_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        memset(&header, 0, sizeof(header));
        header.service.name =
            OpenAPI_service_name_ToString(OpenAPI_service_name_nudm_uecm);
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = udm_ue->supi;
        header.resource.component[1] =
            (char *)OGS_SBI_RESOURCE_NAME_REGISTRATIONS;
        header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_AMF_3GPP_ACCESS;

        if (udm_ue->amf_instance_id &&
            strcmp(udm_ue->amf_instance_id,
                Amf3GppAccessRegistration->amf_instance_id) == 0) {

            status = OGS_SBI_HTTP_STATUS_OK;

        } else {

            if (udm_ue->amf_instance_id)
                ogs_free(udm_ue->amf_instance_id);
            udm_ue->amf_instance_id =
                ogs_strdup(Amf3GppAccessRegistration->amf_instance_id);
            ogs_assert(udm_ue->amf_instance_id);

            status = OGS_SBI_HTTP_STATUS_CREATED;
        }


        if (status == OGS_SBI_HTTP_STATUS_CREATED)
            sendmsg.http.location = ogs_sbi_server_uri(server, &header);

        sendmsg.Amf3GppAccessRegistration =
            OpenAPI_amf3_gpp_access_registration_copy(
                sendmsg.Amf3GppAccessRegistration,
                    udm_ue->amf_3gpp_access_registration);

        response = ogs_sbi_build_response(&sendmsg, status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        ogs_free(sendmsg.http.location);
        OpenAPI_amf3_gpp_access_registration_free(
                sendmsg.Amf3GppAccessRegistration);
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                udm_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

bool udm_nudr_dr_handle_subscription_provisioned(
    udm_ue_t *udm_ue, ogs_sbi_stream_t *stream, int state,
    ogs_sbi_message_t *recvmsg)
{
    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(udm_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    if (state == UDM_SBI_UE_PROVISIONED_DATASETS) {
        OpenAPI_provisioned_data_sets_t *ProvisionedDataSets;

        ProvisionedDataSets = recvmsg->ProvisionedDataSets;
        if (!ProvisionedDataSets) {
            ogs_error("[%s] No ProvisionedDataSets",
                    udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No ProvisionedDataSets",
                    udm_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        sendmsg.ProvisionedDataSets =
            OpenAPI_provisioned_data_sets_copy(
                sendmsg.ProvisionedDataSets,
                    recvmsg->ProvisionedDataSets);

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_provisioned_data_sets_free(sendmsg.ProvisionedDataSets);

        return true;
    }

    SWITCH(recvmsg->h.resource.component[4])
    CASE(OGS_SBI_RESOURCE_NAME_AM_DATA)
        OpenAPI_access_and_mobility_subscription_data_t
            *AccessAndMobilitySubscriptionData = NULL;

        AccessAndMobilitySubscriptionData =
            recvmsg->AccessAndMobilitySubscriptionData;
        if (!AccessAndMobilitySubscriptionData) {
            ogs_error("[%s] No AccessAndMobilitySubscriptionData",
                    udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AccessAndMobilitySubscriptionData",
                    udm_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));

        /* Check if original request was for /nudm-sdm/v2/{supi}/nssai */
        if (state == UDM_SBI_UE_PROVISIONED_NSSAI_ONLY) {
            OpenAPI_nssai_t *Nssai = NULL;
            Nssai = AccessAndMobilitySubscriptionData->nssai;
            if (!Nssai) {
                ogs_error("[%s] No Nssai", udm_ue->supi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No Nssai",
                        udm_ue->supi, NULL));
                return false;
            }

            sendmsg.Nssai = OpenAPI_nssai_copy(sendmsg.Nssai, Nssai);
            response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));
            OpenAPI_nssai_free(sendmsg.Nssai);

            break;
        }

        sendmsg.AccessAndMobilitySubscriptionData =
            OpenAPI_access_and_mobility_subscription_data_copy(
                sendmsg.AccessAndMobilitySubscriptionData,
                    recvmsg->AccessAndMobilitySubscriptionData);

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_access_and_mobility_subscription_data_free(
                sendmsg.AccessAndMobilitySubscriptionData);
        break;

    CASE(OGS_SBI_RESOURCE_NAME_SMF_SELECTION_SUBSCRIPTION_DATA)
        OpenAPI_smf_selection_subscription_data_t *SmfSelectionSubscriptionData;

        SmfSelectionSubscriptionData = recvmsg->SmfSelectionSubscriptionData;
        if (!SmfSelectionSubscriptionData) {
            ogs_error("[%s] No SmfSelectionSubscriptionData", udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No SmfSelectionSubscriptionData",
                    udm_ue->supi, NULL));
            return false;
        }

        memset(&SmfSelectionSubscriptionData, 0,
                sizeof(SmfSelectionSubscriptionData));

        memset(&sendmsg, 0, sizeof(sendmsg));

        sendmsg.SmfSelectionSubscriptionData =
            OpenAPI_smf_selection_subscription_data_copy(
                sendmsg.SmfSelectionSubscriptionData,
                    recvmsg->SmfSelectionSubscriptionData);

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_smf_selection_subscription_data_free(
                sendmsg.SmfSelectionSubscriptionData);
        break;

    CASE(OGS_SBI_RESOURCE_NAME_SM_DATA)
        OpenAPI_lnode_t *node;

        if ((!recvmsg->SessionManagementSubscriptionDataList) ||
            (recvmsg->SessionManagementSubscriptionDataList->count == 0)) {
            ogs_error("[%s] No SessionManagementSubscriptionData",
                    udm_ue->supi);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No SessionManagementSubscriptionData",
                    udm_ue->supi, NULL));
            return false;
        }

        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.SessionManagementSubscriptionDataList = OpenAPI_list_create();

        OpenAPI_list_for_each(recvmsg->SessionManagementSubscriptionDataList, node)
        {
            OpenAPI_session_management_subscription_data_t *item = NULL;

            item = OpenAPI_session_management_subscription_data_copy(item, node->data);
            if (!item) {
                ogs_error("OpenAPI_session_management_subscription_data_copy() "
                        "failed");
                continue;
            }
            OpenAPI_list_add(sendmsg.SessionManagementSubscriptionDataList, item);
        }

        response = ogs_sbi_build_response(&sendmsg, recvmsg->res_status);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        OpenAPI_list_for_each(sendmsg.SessionManagementSubscriptionDataList, node)
            OpenAPI_session_management_subscription_data_free(node->data);
        OpenAPI_list_free(sendmsg.SessionManagementSubscriptionDataList);

        break;

    DEFAULT
        strerror = ogs_msprintf("[%s] Invalid resource name [%s]",
                udm_ue->supi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}

bool udm_nudr_dr_handle_smf_registration(
    udm_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    udm_ue_t *udm_ue = NULL;

    char *strerror = NULL;
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    int status;

    ogs_assert(sess);
    udm_ue = udm_ue_find_by_id(sess->udm_ue_id);
    ogs_assert(udm_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    if (recvmsg->res_status != OGS_SBI_HTTP_STATUS_NO_CONTENT) {
        ogs_error("[%s:%d] HTTP response error [%d]",
            udm_ue->supi, sess->psi, recvmsg->res_status);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, recvmsg->res_status,
                NULL, "HTTP response error", udm_ue->supi,
                (recvmsg->ProblemDetails) ?
                        recvmsg->ProblemDetails->cause : NULL));
        return false;
    }

    SWITCH(recvmsg->h.resource.component[3])
    CASE(OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS)
        SWITCH(recvmsg->h.method)
        CASE(OGS_SBI_HTTP_METHOD_PUT)
            OpenAPI_smf_registration_t *SmfRegistration = NULL;

            SmfRegistration = sess->smf_registration;

            if (!SmfRegistration) {
                ogs_error("[%s:%d] No SmfRegistration", udm_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No SmfRegistration", udm_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->smf_instance_id) {
                ogs_error("[%s:%d] No smfInstanceId", udm_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No smfInstanceId", udm_ue->supi, NULL));
                return false;
            }

            if (ogs_pdu_session_id_is_valid(
                    SmfRegistration->pdu_session_id) == false) {
                ogs_error("[%s:%d] Invalid pduSessionId [%d]",
                        udm_ue->supi, sess->psi,
                        SmfRegistration->pdu_session_id);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "Invalid pduSessionId", udm_ue->supi,
                        NULL));
                return false;
            }

            if (!SmfRegistration->single_nssai) {
                ogs_error("[%s:%d] No singleNssai", udm_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No singleNssai", udm_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->dnn) {
                ogs_error("[%s:%d] No dnn", udm_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No dnn", udm_ue->supi, NULL));
                return false;
            }

            if (!SmfRegistration->plmn_id ||
                    !SmfRegistration->plmn_id->mcc ||
                    !SmfRegistration->plmn_id->mnc) {
                ogs_error("[%s:%d] No plmnId", udm_ue->supi, sess->psi);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(
                        stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        recvmsg, "No plmnId", udm_ue->supi, NULL));
                return false;
            }

            memset(&sendmsg, 0, sizeof(sendmsg));

            memset(&header, 0, sizeof(header));
            header.service.name =
                OpenAPI_service_name_ToString(OpenAPI_service_name_nudm_uecm);
            header.api.version = (char *)OGS_SBI_API_V1;
            header.resource.component[0] = udm_ue->supi;
            header.resource.component[1] =
                (char *)OGS_SBI_RESOURCE_NAME_REGISTRATIONS;
            header.resource.component[2] =
                (char *)OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS;
            header.resource.component[3] = ogs_msprintf("%d", sess->psi);

            if (sess->smf_instance_id &&
                strcmp(sess->smf_instance_id,
                    SmfRegistration->smf_instance_id) == 0) {

                status = OGS_SBI_HTTP_STATUS_OK;

            } else {

                if (sess->smf_instance_id)
                    ogs_free(sess->smf_instance_id);
                sess->smf_instance_id =
                    ogs_strdup(SmfRegistration->smf_instance_id);
                ogs_assert(sess->smf_instance_id);

                status = OGS_SBI_HTTP_STATUS_CREATED;
            }

            if (status == OGS_SBI_HTTP_STATUS_CREATED)
                sendmsg.http.location = ogs_sbi_server_uri(server, &header);

            sendmsg.SmfRegistration = OpenAPI_smf_registration_copy(
                    sendmsg.SmfRegistration, sess->smf_registration);

            response = ogs_sbi_build_response(&sendmsg, status);
            ogs_assert(response);
            ogs_assert(true == ogs_sbi_server_send_response(stream, response));

            ogs_free(header.resource.component[3]);
            ogs_free(sendmsg.http.location);
            OpenAPI_smf_registration_free(sendmsg.SmfRegistration);
            break;

        CASE(OGS_SBI_HTTP_METHOD_DELETE)
            ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));
            break;

        DEFAULT
            ogs_error("[%s:%d] Invalid HTTP method [%s]",
                    udm_ue->suci, sess->psi, recvmsg->h.method);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_FORBIDDEN, recvmsg,
                    "Invalid HTTP method", recvmsg->h.method, NULL));
        END
        break;

    DEFAULT
        strerror = ogs_msprintf("[%s:%d] Invalid resource name [%s]",
                udm_ue->supi, sess->psi, recvmsg->h.resource.component[3]);
        ogs_assert(strerror);

        ogs_error("%s", strerror);
        ogs_assert(true ==
            ogs_sbi_server_send_error(
                stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, strerror, NULL, NULL));
        ogs_free(strerror);
        return false;
    END

    return true;
}
