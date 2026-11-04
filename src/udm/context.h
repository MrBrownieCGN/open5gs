/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef UDM_CONTEXT_H
#define UDM_CONTEXT_H

#include "ogs-app.h"
#include "ogs-crypt.h"
#include "ogs-sbi.h"

#include "udm-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __udm_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __udm_log_domain

typedef struct udm_context_s {
    ogs_list_t      udm_ue_list;
    ogs_list_t      sdm_subscription_list;
    ogs_hash_t      *suci_hash;
    ogs_hash_t      *supi_hash;
    ogs_hash_t      *sdm_subscription_id_hash;

} udm_context_t;

struct udm_ue_s {
    ogs_sbi_object_t sbi;
    ogs_pool_id_t id;
    ogs_fsm_t sm;

    OpenAPI_auth_event_t *auth_event;
    OpenAPI_amf3_gpp_access_registration_t *amf_3gpp_access_registration;

    char *ctx_id;
    char *suci;
    char *supi;
    char *serving_network_name;

    char *ausf_instance_id;
    char *amf_instance_id;

    char *dereg_callback_uri;

    uint8_t k[OGS_KEY_LEN];
    uint8_t opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN];
    uint8_t rand[OGS_RAND_LEN];
    uint8_t sqn[OGS_SQN_LEN];

    ogs_guami_t guami;

    OpenAPI_auth_type_e auth_type;
    OpenAPI_rat_type_e rat_type;

    ogs_list_t sess_list;
    ogs_list_t sdm_subscription_list;

    /*
     * Pending Nudm_UEAU GetHssAv requests (TS 29.503 clause 5.4.2.4) in
     * arrival order. Only the head talks to the UDR; see
     * udm_hss_av_request_t.
     */
    ogs_list_t hss_av_request_list;
};

/*
 * One GetHssAv request of an NF service consumer (HSS).
 *
 * Every request reads the SQN from the UDR and writes the advanced
 * SQN back before the vectors are returned. Two requests for the same
 * SUPI that overlap would read the same SQN and hand out the same SQN
 * range twice, so the requests of one SUPI are served one after the
 * other in arrival order: only the head of udm_ue->hss_av_request_list
 * has a transaction towards the UDR, the others wait until it has been
 * answered.
 *
 * The keys and the SQN are kept here, not in udm_ue->k/opc/amf/sqn/rand,
 * so that a GetHssAv never overwrites the state of a 5G-AKA procedure
 * of the same UE (the AUSF re-synchronisation compares udm_ue->rand).
 */
typedef struct udm_hss_av_request_s {
    ogs_lnode_t lnode;

    /* Stream of the consumer; the UDR transactions are not associated */
    ogs_pool_id_t stream_id;

    int num_of_requested_vectors;

    bool resync_requested;
    uint8_t resync_rand[OGS_RAND_LEN];
    uint8_t resync_auts[OGS_AUTS_LEN];

    uint8_t k[OGS_KEY_LEN];
    uint8_t opc[OGS_KEY_LEN];
    uint8_t amf[OGS_AMF_LEN];
    uint64_t first_sqn;
} udm_hss_av_request_t;

struct udm_sess_s {
    ogs_sbi_object_t sbi;
    ogs_pool_id_t id;
    ogs_fsm_t sm;

    uint8_t psi; /* PDU Session Identity */

    OpenAPI_smf_registration_t *smf_registration;

    char *smf_instance_id;

    /* Related Context */
    ogs_pool_id_t udm_ue_id;
};

typedef struct udm_sdm_subscription_s {
    ogs_lnode_t lnode;

    char *id;
    char *data_change_callback_uri;

    udm_ue_t *udm_ue;
} udm_sdm_subscription_t;

void udm_context_init(void);
void udm_context_final(void);
udm_context_t *udm_self(void);

int udm_context_parse_config(void);

udm_ue_t *udm_ue_add(char *suci);
void udm_ue_remove(udm_ue_t *udm_ue);
void udm_ue_remove_all(void);
udm_ue_t *udm_ue_find_by_suci(char *suci);
udm_ue_t *udm_ue_find_by_supi(char *supi);
udm_ue_t *udm_ue_find_by_ctx_id(char *ctx_id);

udm_sess_t *udm_sess_add(udm_ue_t *udm_ue, uint8_t psi);
void udm_sess_remove(udm_sess_t *sess);
void udm_sess_remove_all(udm_ue_t *udm_ue);
udm_sess_t *udm_sess_find_by_psi(udm_ue_t *udm_ue, uint8_t psi);

udm_ue_t *udm_ue_find_by_id(ogs_pool_id_t id);
udm_sess_t *udm_sess_find_by_id(ogs_pool_id_t id);

udm_sdm_subscription_t *udm_sdm_subscription_add(udm_ue_t *udm_ue);
void udm_sdm_subscription_remove(udm_sdm_subscription_t *subscription);
void udm_sdm_subscription_remove_all(udm_ue_t *udm_ue);
udm_sdm_subscription_t *udm_sdm_subscription_find_by_id(char *id);

udm_hss_av_request_t *udm_hss_av_request_add(
        udm_ue_t *udm_ue, ogs_sbi_stream_t *stream);
void udm_hss_av_request_remove(
        udm_ue_t *udm_ue, udm_hss_av_request_t *request);
void udm_hss_av_request_abort_all(udm_ue_t *udm_ue);
udm_hss_av_request_t *udm_hss_av_request_head(udm_ue_t *udm_ue);

bool udm_ue_is_unused(udm_ue_t *udm_ue);

int get_ue_load(void);

#ifdef __cplusplus
}
#endif

#endif /* UDM_CONTEXT_H */
