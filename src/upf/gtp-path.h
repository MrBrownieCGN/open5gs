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

#ifndef UPF_GTP_PATH_H
#define UPF_GTP_PATH_H

#include "ogs-tun.h"
#include "ogs-gtp.h"

#ifdef __cplusplus
extern "C" {
#endif

int upf_gtp_init(void);
void upf_gtp_final(void);

int upf_gtp_open(void);
void upf_gtp_close(void);

/* Open the TUN device for `dev` if it has not been opened yet.
 * Returns OGS_OK in both the "already open" and "successfully opened
 * now" cases. Used by the runtime DNN reload path to attach a new
 * device without disturbing devices opened at cold-start. */
int upf_gtp_open_dev_if_new(ogs_pfcp_dev_t *dev);

/* Configure the IP address on the TUN device for `subnet`. Wraps
 * ogs_tun_set_ip() — on Linux this is a no-op (the address/route is
 * managed externally by the operator's network configuration). */
int upf_gtp_set_subnet_ip(ogs_pfcp_subnet_t *subnet);

#ifdef __cplusplus
}
#endif

#endif /* UPF_GTP_PATH_H */
