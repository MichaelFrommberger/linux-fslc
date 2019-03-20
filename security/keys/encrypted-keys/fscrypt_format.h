/*
 * fscrypt_format.h: helper functions for the encrypted fscrypt key type
 *
 * Copyright (C) 2017 Diehl Metering GmbH
 *
 * Authors:
 * Michael Frommberger <michael.frommberger@diehl.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef __KEYS_FSCRYPT_H
#define __KEYS_FSCRYPT_H

#include <linux/fscrypto.h>

u8 *fscrypt_get_enc_key(struct fscrypt_key *enc_key);
int fscrypt_fill_enc_key(struct fscrypt_key *enc_key);

#endif				/* __KEYS_FSCRYPT_H */
