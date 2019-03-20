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

#include <linux/module.h>
#include "fscrypt_format.h"

u8 *fscrypt_get_enc_key(struct fscrypt_key *enc_key)
{
	return enc_key->raw;
}
EXPORT_SYMBOL(fscrypt_get_enc_key);

/*
 * fscrypt_fill_enc_key - fill the fscrypt_key structure
 *
 * Fill the fscrypt_key structure with required fscrypt data.
 */
int fscrypt_fill_enc_key(struct fscrypt_key *enc_key)
{
  /* 
   * fill in mode: value from e4crypt
   * (ignored in the kernel at the moment) 
   */
  enc_key->mode = FS_ENCRYPTION_MODE_AES_256_XTS;
  enc_key->size = FS_MAX_KEY_SIZE;

  return 0;
}
EXPORT_SYMBOL(fscrypt_fill_enc_key);

MODULE_LICENSE("GPL");
