/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
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
#include "gtp-path.h"
#include "pfcp-path.h"
#include "metrics.h"

static ogs_thread_t *thread;
static void upf_main(void *data);

static int initialized = 0;

int upf_initialize(void)
{
    int rv;

#define APP_NAME "upf"
    rv = ogs_app_parse_local_conf(APP_NAME);
    if (rv != OGS_OK) return rv;

    upf_metrics_init();

    ogs_gtp_context_init(OGS_MAX_NUM_OF_GTPU_RESOURCE);
    ogs_pfcp_context_init();

    upf_context_init();
    upf_event_init();
    upf_gtp_init();

    rv = ogs_pfcp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config(APP_NAME, "smf");
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config(APP_NAME, "smf");
    if (rv != OGS_OK) return rv;

    rv = ogs_metrics_context_parse_config(APP_NAME);
    if (rv != OGS_OK) return rv;

    rv = upf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_ue_pool_generate();
    if (rv != OGS_OK) return rv;

    ogs_metrics_context_open(ogs_metrics_self());

    rv = upf_pfcp_open();
    if (rv != OGS_OK) return rv;

    rv = upf_gtp_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(upf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

/******************************************************************************
 * upf_reload()
 *
 * Apply runtime DNN/APN additions from the YAML configuration without
 * tearing down active sessions. Called from the main-loop FSM dispatcher
 * (upf_state_operational, OGS_EVENT_APP_RELOAD) — never directly from
 * the signal-thread; the signal-thread only enqueues the event via
 * app_reload() in src/upf/app.c.
 *
 * Add-only: existing DNNs are not mutated. Drift on existing DNNs is
 * detected by ogs_pfcp_context_reload_config() and warned but not
 * honored (live ue_ip->subnet pointers must not be invalidated).
 *
 * Per-subnet rollback: if a newly-added DNN fails any apply step, only
 * that subnet is removed via ogs_pfcp_subnet_remove(). Other newly-added
 * DNNs and all existing DNNs remain unaffected. ogs_list_for_each_safe
 * is mandatory because the loop body may free `subnet`.
 *
 * Known Phase-1 limitation: if a runtime-added DNN brought a brand-new
 * ifname (e.g. ogstun2) and the dev was opened successfully but the
 * subsequent set_subnet_ip() or pool_generate fails, the new
 * ogs_pfcp_dev_t is left in self.dev_list with the underlying TUN
 * interface open. Most deployments share `ogstun` for all DNNs so this
 * path is rare. Phase 2 introduces dev refcounting to close cleanly.
 ******************************************************************************/
int upf_reload(void)
{
    int rv;
    ogs_pfcp_reload_result_t result;
    ogs_list_t added;
    ogs_pfcp_subnet_t *subnet = NULL, *next = NULL;

    ogs_list_init(&added);
    memset(&result, 0, sizeof(result));

    rv = ogs_pfcp_context_reload_config(
            "upf", "smf", &added, &result);
    if (rv != OGS_OK) {
        ogs_error("UPF reload aborted: parse failure (%d)", rv);
        return rv;
    }

    if (result.added == 0) {
        ogs_info("UPF reload: no new DNNs "
                "(unchanged=%d, drift=%d, errors=%d)",
                result.unchanged, result.drift, result.errors);
        return OGS_OK;
    }

    ogs_list_for_each_safe(&added, next, subnet) {
        rv = upf_gtp_open_dev_if_new(subnet->dev);
        if (rv != OGS_OK) goto rollback_one;

        rv = upf_gtp_set_subnet_ip(subnet);
        if (rv != OGS_OK) goto rollback_one;

        rv = ogs_pfcp_ue_pool_generate_for_subnet(subnet);
        if (rv != OGS_OK) goto rollback_one;

        ogs_info("DNN '%s' added at runtime "
                "(NOTE: on Linux, external OS routing for the new "
                "UE pool must be configured separately — "
                "ogs_tun_set_ip() is a no-op on Linux)",
                subnet->dnn);
        continue;

rollback_one:
        ogs_error("Failed to apply runtime-added DNN '%s'; "
                "rolling back this subnet only "
                "(other DNNs and active sessions unaffected)",
                subnet->dnn);
        /* De-link from added before subnet_remove() frees it,
         * to avoid any list-traversal use-after-free. */
        ogs_list_remove(&added, subnet);
        ogs_pfcp_subnet_remove(subnet);
        result.errors++;
        result.added--;
    }

    ogs_info("UPF reload complete: "
            "added=%d, unchanged=%d, drift=%d, errors=%d",
            result.added, result.unchanged, result.drift, result.errors);
    return result.errors ? OGS_ERROR : OGS_OK;
}

void upf_terminate(void)
{
    if (!initialized) return;

    upf_event_term();

    ogs_thread_destroy(thread);

    upf_pfcp_close();
    upf_gtp_close();

    ogs_metrics_context_close(ogs_metrics_self());

    upf_context_final();

    ogs_pfcp_context_final();
    ogs_gtp_context_final();

    ogs_pfcp_xact_final();

    upf_gtp_final();
    upf_event_final();

    upf_metrics_final();
}

static void upf_main(void *data)
{
    ogs_fsm_t upf_sm;
    int rv;

    ogs_fsm_init(&upf_sm, upf_state_initial, upf_state_final, 0);

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
            upf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&upf_sm, e);
            upf_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&upf_sm, 0);
}
