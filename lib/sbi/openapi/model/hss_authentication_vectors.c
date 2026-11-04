
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hss_authentication_vectors.h"

OpenAPI_hss_authentication_vectors_t *OpenAPI_hss_authentication_vectors_create(
    OpenAPI_list_t *av_eps_aka_list,
    OpenAPI_list_t *av_ims_gba_eap_aka_list,
    OpenAPI_list_t *av_eap_aka_prime_list
)
{
    OpenAPI_hss_authentication_vectors_t *hss_authentication_vectors_local_var = ogs_malloc(sizeof(OpenAPI_hss_authentication_vectors_t));
    ogs_assert(hss_authentication_vectors_local_var);

    hss_authentication_vectors_local_var->av_eps_aka_list = av_eps_aka_list;
    hss_authentication_vectors_local_var->av_ims_gba_eap_aka_list = av_ims_gba_eap_aka_list;
    hss_authentication_vectors_local_var->av_eap_aka_prime_list = av_eap_aka_prime_list;

    return hss_authentication_vectors_local_var;
}

void OpenAPI_hss_authentication_vectors_free(OpenAPI_hss_authentication_vectors_t *hss_authentication_vectors)
{
    OpenAPI_lnode_t *node = NULL;

    if (NULL == hss_authentication_vectors) {
        return;
    }
    if (hss_authentication_vectors->av_eps_aka_list) {
        OpenAPI_list_for_each(hss_authentication_vectors->av_eps_aka_list, node) {
            OpenAPI_av_eps_aka_free(node->data);
        }
        OpenAPI_list_free(hss_authentication_vectors->av_eps_aka_list);
        hss_authentication_vectors->av_eps_aka_list = NULL;
    }
    if (hss_authentication_vectors->av_ims_gba_eap_aka_list) {
        OpenAPI_list_for_each(hss_authentication_vectors->av_ims_gba_eap_aka_list, node) {
            OpenAPI_av_ims_gba_eap_aka_free(node->data);
        }
        OpenAPI_list_free(hss_authentication_vectors->av_ims_gba_eap_aka_list);
        hss_authentication_vectors->av_ims_gba_eap_aka_list = NULL;
    }
    if (hss_authentication_vectors->av_eap_aka_prime_list) {
        OpenAPI_list_for_each(hss_authentication_vectors->av_eap_aka_prime_list, node) {
            OpenAPI_av_eap_aka_prime_free(node->data);
        }
        OpenAPI_list_free(hss_authentication_vectors->av_eap_aka_prime_list);
        hss_authentication_vectors->av_eap_aka_prime_list = NULL;
    }
    ogs_free(hss_authentication_vectors);
}

/*
 * oneOf union (x-open5gs-union): the members are the alternatives of the
 * original oneOf. Exactly one is set, and it is the JSON value itself
 * rather than a property of a wrapper object.
 */
cJSON *OpenAPI_hss_authentication_vectors_convertToJSON(OpenAPI_hss_authentication_vectors_t *hss_authentication_vectors)
{
    cJSON *item = NULL;
    OpenAPI_lnode_t *node = NULL;

    if (hss_authentication_vectors == NULL) {
        ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [HssAuthenticationVectors]");
        return NULL;
    }

    if ((hss_authentication_vectors->av_eps_aka_list != NULL) +
            (hss_authentication_vectors->av_ims_gba_eap_aka_list != NULL) +
            (hss_authentication_vectors->av_eap_aka_prime_list != NULL) != 1) {
        ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [HssAuthenticationVectors]: exactly one alternative must be set");
        return NULL;
    }

    if (hss_authentication_vectors->av_eps_aka_list) {
        item = cJSON_CreateArray();
        if (item == NULL) {
            ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_eps_aka_list]");
            return NULL;
        }
        OpenAPI_list_for_each(hss_authentication_vectors->av_eps_aka_list, node) {
            cJSON *itemLocal = OpenAPI_av_eps_aka_convertToJSON(node->data);
            if (itemLocal == NULL) {
                ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_eps_aka_list]");
                cJSON_Delete(item);
                return NULL;
            }
            cJSON_AddItemToArray(item, itemLocal);
        }
        return item;
    }
    if (hss_authentication_vectors->av_ims_gba_eap_aka_list) {
        item = cJSON_CreateArray();
        if (item == NULL) {
            ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_ims_gba_eap_aka_list]");
            return NULL;
        }
        OpenAPI_list_for_each(hss_authentication_vectors->av_ims_gba_eap_aka_list, node) {
            cJSON *itemLocal = OpenAPI_av_ims_gba_eap_aka_convertToJSON(node->data);
            if (itemLocal == NULL) {
                ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_ims_gba_eap_aka_list]");
                cJSON_Delete(item);
                return NULL;
            }
            cJSON_AddItemToArray(item, itemLocal);
        }
        return item;
    }
    if (hss_authentication_vectors->av_eap_aka_prime_list) {
        item = cJSON_CreateArray();
        if (item == NULL) {
            ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_eap_aka_prime_list]");
            return NULL;
        }
        OpenAPI_list_for_each(hss_authentication_vectors->av_eap_aka_prime_list, node) {
            cJSON *itemLocal = OpenAPI_av_eap_aka_prime_convertToJSON(node->data);
            if (itemLocal == NULL) {
                ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [av_eap_aka_prime_list]");
                cJSON_Delete(item);
                return NULL;
            }
            cJSON_AddItemToArray(item, itemLocal);
        }
        return item;
    }

    ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed [HssAuthenticationVectors]");
    return NULL;
}

OpenAPI_hss_authentication_vectors_t *OpenAPI_hss_authentication_vectors_parseFromJSON(cJSON *hss_authentication_vectorsJSON)
{
    OpenAPI_lnode_t *node = NULL;
    OpenAPI_list_t *av_eps_aka_list = NULL;
    OpenAPI_list_t *av_ims_gba_eap_aka_list = NULL;
    OpenAPI_list_t *av_eap_aka_prime_list = NULL;

    if (cJSON_IsArray(hss_authentication_vectorsJSON) &&
            cJSON_IsObject(cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0)) &&
            cJSON_GetObjectItemCaseSensitive(
                cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0), "kasme")) {
        cJSON *av_eps_aka_list_local = NULL;

        av_eps_aka_list = OpenAPI_list_create();

        cJSON_ArrayForEach(av_eps_aka_list_local, hss_authentication_vectorsJSON) {
            if (!cJSON_IsObject(av_eps_aka_list_local) ||
                    !cJSON_GetObjectItemCaseSensitive(
                        av_eps_aka_list_local, "kasme")) {
                ogs_error("OpenAPI_hss_authentication_vectors_parseFromJSON() failed [av_eps_aka_list]");
                goto end;
            }
            OpenAPI_av_eps_aka_t *av_eps_aka_listItem = OpenAPI_av_eps_aka_parseFromJSON(av_eps_aka_list_local);
            if (!av_eps_aka_listItem) {
                ogs_error("No av_eps_aka_listItem");
                goto end;
            }
            OpenAPI_list_add(av_eps_aka_list, av_eps_aka_listItem);
        }
    } else if (cJSON_IsArray(hss_authentication_vectorsJSON) &&
            cJSON_IsObject(cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0)) &&
            cJSON_GetObjectItemCaseSensitive(
                cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0), "ck")) {
        cJSON *av_ims_gba_eap_aka_list_local = NULL;

        av_ims_gba_eap_aka_list = OpenAPI_list_create();

        cJSON_ArrayForEach(av_ims_gba_eap_aka_list_local, hss_authentication_vectorsJSON) {
            if (!cJSON_IsObject(av_ims_gba_eap_aka_list_local) ||
                    !cJSON_GetObjectItemCaseSensitive(
                        av_ims_gba_eap_aka_list_local, "ck")) {
                ogs_error("OpenAPI_hss_authentication_vectors_parseFromJSON() failed [av_ims_gba_eap_aka_list]");
                goto end;
            }
            OpenAPI_av_ims_gba_eap_aka_t *av_ims_gba_eap_aka_listItem = OpenAPI_av_ims_gba_eap_aka_parseFromJSON(av_ims_gba_eap_aka_list_local);
            if (!av_ims_gba_eap_aka_listItem) {
                ogs_error("No av_ims_gba_eap_aka_listItem");
                goto end;
            }
            OpenAPI_list_add(av_ims_gba_eap_aka_list, av_ims_gba_eap_aka_listItem);
        }
    } else if (cJSON_IsArray(hss_authentication_vectorsJSON) &&
            cJSON_IsObject(cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0)) &&
            cJSON_GetObjectItemCaseSensitive(
                cJSON_GetArrayItem(hss_authentication_vectorsJSON, 0), "ckPrime")) {
        cJSON *av_eap_aka_prime_list_local = NULL;

        av_eap_aka_prime_list = OpenAPI_list_create();

        cJSON_ArrayForEach(av_eap_aka_prime_list_local, hss_authentication_vectorsJSON) {
            if (!cJSON_IsObject(av_eap_aka_prime_list_local) ||
                    !cJSON_GetObjectItemCaseSensitive(
                        av_eap_aka_prime_list_local, "ckPrime")) {
                ogs_error("OpenAPI_hss_authentication_vectors_parseFromJSON() failed [av_eap_aka_prime_list]");
                goto end;
            }
            OpenAPI_av_eap_aka_prime_t *av_eap_aka_prime_listItem = OpenAPI_av_eap_aka_prime_parseFromJSON(av_eap_aka_prime_list_local);
            if (!av_eap_aka_prime_listItem) {
                ogs_error("No av_eap_aka_prime_listItem");
                goto end;
            }
            OpenAPI_list_add(av_eap_aka_prime_list, av_eap_aka_prime_listItem);
        }
    } else {
        ogs_error("OpenAPI_hss_authentication_vectors_parseFromJSON() failed [HssAuthenticationVectors]");
        goto end;
    }

    return OpenAPI_hss_authentication_vectors_create(av_eps_aka_list, av_ims_gba_eap_aka_list, av_eap_aka_prime_list);
end:
    if (av_eps_aka_list) {
        OpenAPI_list_for_each(av_eps_aka_list, node) {
            OpenAPI_av_eps_aka_free(node->data);
        }
        OpenAPI_list_free(av_eps_aka_list);
        av_eps_aka_list = NULL;
    }
    if (av_ims_gba_eap_aka_list) {
        OpenAPI_list_for_each(av_ims_gba_eap_aka_list, node) {
            OpenAPI_av_ims_gba_eap_aka_free(node->data);
        }
        OpenAPI_list_free(av_ims_gba_eap_aka_list);
        av_ims_gba_eap_aka_list = NULL;
    }
    if (av_eap_aka_prime_list) {
        OpenAPI_list_for_each(av_eap_aka_prime_list, node) {
            OpenAPI_av_eap_aka_prime_free(node->data);
        }
        OpenAPI_list_free(av_eap_aka_prime_list);
        av_eap_aka_prime_list = NULL;
    }
    return NULL;
}

OpenAPI_hss_authentication_vectors_t *OpenAPI_hss_authentication_vectors_copy(OpenAPI_hss_authentication_vectors_t *dst, OpenAPI_hss_authentication_vectors_t *src)
{
    cJSON *item = NULL;
    char *content = NULL;

    ogs_assert(src);
    item = OpenAPI_hss_authentication_vectors_convertToJSON(src);
    if (!item) {
        ogs_error("OpenAPI_hss_authentication_vectors_convertToJSON() failed");
        return NULL;
    }

    content = cJSON_Print(item);
    cJSON_Delete(item);

    if (!content) {
        ogs_error("cJSON_Print() failed");
        return NULL;
    }

    item = cJSON_Parse(content);
    ogs_free(content);
    if (!item) {
        ogs_error("cJSON_Parse() failed");
        return NULL;
    }

    OpenAPI_hss_authentication_vectors_free(dst);
    dst = OpenAPI_hss_authentication_vectors_parseFromJSON(item);
    cJSON_Delete(item);

    return dst;
}

