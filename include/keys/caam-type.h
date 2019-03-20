/*
 * Copyright (C) 2017 Diehl Metering GmbH
 * Author: Michael Frommberger <michael.frommberger@diehl.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef _KEYS_CAAM_TYPE_H
#define _KEYS_CAAM_TYPE_H

#include <linux/key.h>
#include <linux/rcupdate.h>

/* blob key +  MAC */
#define BLOB_OVERHEAD (32 + 16)

#define MAX_BLOB_SIZE			(1 << CONFIG_CRYPTO_DEV_FSL_CAAM_SM_SLOTSIZE)
#define MAX_RAWKEY_SIZE		(MAX_BLOB_SIZE - BLOB_OVERHEAD)
#define MIN_RAWKEY_SIZE		1 

enum key_color_type {
  RED_KEY = 0,
  BLACK_KEY = 1,
  UNKNOWN_KEY = 2
};

struct caam_key_payload {
	struct rcu_head rcu;
	unsigned int rawkey_len;
	unsigned int blob_len;
	enum key_color_type color;
	unsigned char rawkey[MAX_RAWKEY_SIZE + 1];
	unsigned char blob[MAX_BLOB_SIZE];
};

extern struct key_type key_type_caam;

#endif /* _KEYS_CAAM_TYPE_H */
