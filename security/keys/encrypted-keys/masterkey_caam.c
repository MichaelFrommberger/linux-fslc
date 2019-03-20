/*
 * Copyright (C) 2017 Diehl Metering GmbH
 *
 * Authors:
 * Michael Frommberger <michael.frommberger@diehl.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * See Documentation/security/keys-caam-encrypted.txt
 *
 * Based on masterkey_trusted.c
 */

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/err.h>
#include <keys/caam-type.h>
#include <keys/encrypted-type.h>
#include "encrypted.h"

/*
 * request_caam_key - request the caam key
 *
 * Caam keys are encrypted with a device specific key. Although userspace
 * manages both caam/encrypted key-types, like the encrypted key type
 * data, caam key type data is not visible decrypted from userspace.
 */
struct key *request_caam_key(const char *caam_desc,
				const u8 **master_key, size_t *master_keylen)
{
	struct caam_key_payload *cpayload;
	struct key *ckey;

	ckey = request_key(&key_type_caam, caam_desc, NULL);
	if (IS_ERR(ckey))
		goto error;

	down_read(&ckey->sem);
	cpayload = ckey->payload.data[0];
	*master_key = cpayload->rawkey;
	*master_keylen = cpayload->rawkey_len;
error:
	return ckey;
}
