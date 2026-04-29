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

    rv = upf_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to initialize UPF");
        return rv;
    }
    ogs_info("UPF initialize...done");

    return OGS_OK;
}

void app_terminate(void)
{
    upf_terminate();
    ogs_info("UPF terminate...done");
}

int app_reload(void)
{
    upf_event_t *e;
    int rv;

    /* Runs in the signal-thread. Do not touch UPF/PFCP state here —
     * enqueue an OGS_EVENT_APP_RELOAD event and let the main-loop
     * FSM dispatcher (single-writer of self.subnet_list, dev_list,
     * and TUN devices) perform the reload safely. */
    e = upf_event_new((upf_event_e)OGS_EVENT_APP_RELOAD);
    if (!e) {
        ogs_error("upf_event_new(OGS_EVENT_APP_RELOAD) failed");
        return OGS_ERROR;
    }

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed for reload event: rv=%d", rv);
        upf_event_free(e);
        return rv;
    }
    ogs_pollset_notify(ogs_app()->pollset);

    return OGS_OK;
}
