/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "ogs-app.h"
#include "event.h"

int app_initialize(const char *const argv[])
{
    int rv;

    rv = smf_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to initialize SMF");
        return rv;
    }
    ogs_info("SMF initialize...done");

    return OGS_OK;
}

void app_terminate(void)
{
    smf_terminate();
    ogs_info("SMF terminate...done");
}

int app_reload(void)
{
    smf_event_t *e;
    int rv;

    /* Runs in the signal-thread. Do not touch SMF/PFCP/SBI state here —
     * enqueue an OGS_EVENT_APP_RELOAD event and let the main-loop
     * FSM dispatcher (single-writer of self.subnet_list and the SBI
     * nf_instance state) perform the reload safely. */
    e = smf_event_new(OGS_EVENT_APP_RELOAD);
    if (!e) {
        ogs_error("smf_event_new(OGS_EVENT_APP_RELOAD) failed");
        return OGS_ERROR;
    }

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed for reload event: rv=%d", rv);
        ogs_event_free(e);
        return rv;
    }
    ogs_pollset_notify(ogs_app()->pollset);

    return OGS_OK;
}
