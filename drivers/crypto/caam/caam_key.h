/*
 * Copyright (C) 2017 Diehl Metering GmbH
 * Author: Michael Frommberger <michael.frommberger@diehl.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef __CAAM_KEY_H
#define __CAAM_KEY_H

#define MAX_KEYMOD_SIZE		(16)
#define MIN_KEYMOD_SIZE		(8)

/* cover types for BLACK_KEY */
enum key_cover_type {
	AES_ECB = 0,
	AES_CCM = 1,
	UNKNOWN = 2
};

struct caam_key_options {
	unsigned int keymod_len;
	enum key_cover_type cover;
	unsigned char keymod[MAX_KEYMOD_SIZE + 1];
};

const char *key_color_name[] = { "RED_KEY", "BLACK_KEY" };
const char *key_cover_name[] = { "AES_ECB", "AES_CCM" };

#undef CAAM_KEY_DEBUG

#ifdef CAAM_KEY_DEBUG

static inline void dump_options(struct caam_key_options *o)
{
	pr_info("caam_key: keymod_len %d\n", o->keymod_len);
	print_hex_dump(KERN_INFO, "caam_key: keymod ", DUMP_PREFIX_NONE,
		       16, 1, o->keymod, o->keymod_len, 0);
	pr_info("caam_key: cover %s\n", key_cover_name[o->cover]);
}

static inline void dump_payload(struct caam_key_payload *p)
{
	pr_info("caam_key: rawkey_len %d\n", p->rawkey_len);
	print_hex_dump(KERN_INFO, "caam_key: rawkey ", DUMP_PREFIX_NONE,
		       16, 1, p->rawkey, p->rawkey_len, 0);
	pr_info("caam_key: bloblen %d\n", p->blob_len);
	print_hex_dump(KERN_INFO, "caam_key: blob ", DUMP_PREFIX_NONE,
		       16, 1, p->blob, p->blob_len, 0);
	pr_info("caam_key: color %s\n", key_color_name[p->color]);
}

#else				/* CAAM_KEY_DEBUG */

static inline void dump_options(struct caam_key_options *o)
{
}

static inline void dump_payload(struct caam_key_payload *p)
{
}

#endif				/* CAAM_KEY_DEBUG */

#endif				/* __CAAM_KEY_H */
