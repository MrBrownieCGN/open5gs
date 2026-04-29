/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "context.h"
#include "fd-path.h"
#include "gtp-path.h"
#include "pfcp-path.h"
#include "sbi-path.h"
#include "metrics.h"
#include "ogs-metrics.h"
#include "metrics/prometheus/json_pager.h"
#include "pdu-info.h"

static ogs_thread_t *thread;
static void smf_main(void *data);

static int initialized = 0;

int smf_initialize(void)
{
    int rv;

#define APP_NAME "smf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    smf_metrics_init();

    ogs_gtp_context_init(ogs_app()->pool.nf * OGS_MAX_NUM_OF_GTPU_RESOURCE);
    ogs_pfcp_context_init();
    ogs_sbi_context_init(OpenAPI_nf_type_SMF);

    smf_context_init();

    rv = ogs_gtp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "upf");
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config(APP_NAME, "upf");
    if (rv != OGS_OK) return rv;

    rv = ogs_sbi_context_parse_config(APP_NAME, "nrf", "scp");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = smf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_ue_pool_generate();
    if (rv != OGS_OK) return rv;

    ogs_metrics_context_open(ogs_metrics_self());

    rv = smf_fd_init();
    if (rv != 0) return OGS_ERROR;

    rv = smf_gtp_open();
    if (rv != 0) return OGS_ERROR;

    rv = smf_pfcp_open();
    if (rv != 0) return OGS_ERROR;

    rv = smf_sbi_open();
    if (rv != 0) return OGS_ERROR;

    thread = ogs_thread_create(smf_main, NULL);
    if (!thread) return OGS_ERROR;

    /* dumper /pdu-info */
    ogs_metrics_register_custom_ep(smf_dump_pdu_info, "/pdu-info");

    initialized = 1;

    return OGS_OK;
}

/******************************************************************************
 * smf_reload()
 *
 * Apply runtime DNN/APN additions from the YAML configuration without
 * tearing down active sessions. Called from the main-loop FSM dispatcher
 * (smf_state_operational, OGS_EVENT_APP_RELOAD) — never directly from
 * the signal-thread; the signal-thread only enqueues the event via
 * app_reload() in src/smf/app.c.
 *
 * Add-only on the subnet side, with mandatory NF-profile update so the
 * AMF discovers the new DNN list immediately (without waiting for the
 * next periodic NRF heartbeat).
 *
 * Per-subnet rollback on UE pool generation failure mirrors the UPF path.
 ******************************************************************************/
int smf_reload(void)
{
    int rv;
    ogs_pfcp_reload_result_t result;
    ogs_list_t added;
    ogs_pfcp_subnet_t *subnet = NULL, *next = NULL;

    ogs_list_init(&added);
    memset(&result, 0, sizeof(result));

    rv = ogs_pfcp_context_reload_config(
            "smf", "upf", &added, &result);
    if (rv != OGS_OK) {
        ogs_error("SMF reload aborted: parse failure (%d)", rv);
        return rv;
    }

    if (result.added == 0) {
        ogs_info("SMF reload: no new DNNs "
                "(unchanged=%d, drift=%d, errors=%d)",
                result.unchanged, result.drift, result.errors);
        return OGS_OK;
    }

    /* Generate the UE pool for each newly-added subnet. Per-subnet
     * rollback to keep partial-success behaviour consistent with UPF. */
    ogs_list_for_each_safe(&added, next, subnet) {
        rv = ogs_pfcp_ue_pool_generate_for_subnet(subnet);
        if (rv != OGS_OK) {
            ogs_error("Failed to generate UE pool for DNN '%s'; "
                    "rolling back this subnet only "
                    "(other DNNs unaffected)", subnet->dnn);
            ogs_list_remove(&added, subnet);
            ogs_pfcp_subnet_remove(subnet);
            result.errors++;
            result.added--;
        } else {
            ogs_info("DNN '%s' added at runtime (SMF side)",
                    subnet->dnn);
        }
    }

    /* Append the new DNNs to slice[0].dnn[] in the SMF NF profile so
     * that the NRF update below advertises them to AMFs. */
    rv = smf_context_reload_info_dnn_mapping(&added);
    if (rv != OGS_OK) {
        ogs_error("Failed to refresh slice→DNN mapping in SMF nf_info; "
                "subnets added but AMF discovery may be stale until "
                "restart");
    }

    /* Trigger an NRF NF-profile update so the AMF discovers this SMF
     * for the new DNNs immediately. Guard with OGS_FSM_CHECK because
     * SIGHUP can arrive in any NF state — including during initial
     * registration (FSM in will_register) or after an SBI link-down
     * (FSM in de_registered). The guard mirrors the heartbeat handler
     * pattern in lib/sbi/nf-sm.c (which uses the same OGS_FSM_CHECK
     * before dispatching profile updates). */
    {
        ogs_sbi_nf_instance_t *nf_instance =
            ogs_sbi_self() ? ogs_sbi_self()->nf_instance : NULL;

        if (nf_instance &&
            OGS_FSM_CHECK(&nf_instance->sm, ogs_sbi_nf_state_registered)) {
            if (ogs_nnrf_nfm_send_nf_update(nf_instance) == true) {
                ogs_info("NRF NF profile update sent with new DNN list");
            } else {
                ogs_error("NRF NF profile update failed after reload; "
                        "AMF may not discover this SMF for new DNNs "
                        "until next heartbeat (non-fatal — heartbeat "
                        "will resync within ~30s)");
            }
        } else {
            ogs_info("SMF not currently registered with NRF; new DNNs "
                    "will be published on the next NRF registration");
        }
    }

    ogs_info("SMF reload complete: "
            "added=%d, unchanged=%d, drift=%d, errors=%d",
            result.added, result.unchanged, result.drift, result.errors);
    return result.errors ? OGS_ERROR : OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        ogs_sbi_nf_fsm_fini(nf_instance);

    /* Gracefully shutdown the server by sending GOAWAY to each session. */
    ogs_sbi_server_graceful_shutdown_all();

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(ogs_app()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
#define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    /* Sending termination event to the queue */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void smf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    smf_gtp_close();
    smf_pfcp_close();
    smf_sbi_close();

    ogs_metrics_context_close(ogs_metrics_self());

    smf_fd_final();

    smf_context_final();

    ogs_pfcp_context_final();
    ogs_sbi_context_final();
    ogs_gtp_context_final();

    ogs_pfcp_xact_final();
    ogs_gtp_xact_final();

    smf_metrics_final();
}

static void smf_main(void *data)
{
    ogs_fsm_t smf_sm;
    int rv;

    ogs_fsm_init(&smf_sm, smf_state_initial, smf_state_final, 0);

    for ( ;; ) {
        ogs_pollset_poll(ogs_app()->pollset,
                ogs_timer_mgr_next(ogs_app()->timer_mgr));

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the current value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for ( ;; ) {
            smf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&smf_sm, e);
            ogs_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&smf_sm, 0);
}
