/*
 * Copyright (C) 2017 Diehl Metering GmbH
 * Author: Michael Frommberger <michael.frommberger@diehl.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/err.h>
#include <keys/user-type.h>
#include <keys/caam-type.h>
#include <linux/key-type.h>

#include "caam_key.h"
#include "compat.h"
#include "intern.h"
#include "jr.h"
#include "sm.h"

enum {
	Opt_err = -1,
	Opt_new, Opt_load,
	Opt_color, Opt_keymod, Opt_cover
};

static const match_table_t key_tokens = {
	{Opt_new, "new"},
	{Opt_load, "load"},
	{Opt_color, "color=%s"},
	{Opt_keymod, "keymod=%s"},
	{Opt_cover, "cover=%s"},
	{Opt_err, NULL}
};

/* default key modifier */
static u8 def_keymod[] = {
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};

/* can have zero or more token= options */
static int getoptions(char *c, struct caam_key_payload *pay,
		      struct caam_key_options *opt)
{
	substring_t args[MAX_OPT_ARGS];
	char *p = c;
	int token;
	int res;
	enum key_color_type color = RED_KEY;
	unsigned int keymod_len;
	enum key_cover_type cover = AES_ECB;

	while ((p = strsep(&c, " \t"))) {
		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;
		token = match_token(p, key_tokens, args);

		switch (token) {
		case Opt_color:
			for (color = RED_KEY; color < UNKNOWN_KEY; color++) {
				if (0 ==
				    strcmp(args[0].from, key_color_name[color]))
					break;
			}
			if (UNKNOWN_KEY == color)
				return -EINVAL;
			pay->color = color;
			break;

		case Opt_keymod:
			keymod_len = strlen(args[0].from) / 2;
			if (MIN_KEYMOD_SIZE > keymod_len
			    || MAX_KEYMOD_SIZE < keymod_len)
				return -EINVAL;
			res = hex2bin(opt->keymod, args[0].from, keymod_len);
			if (res < 0)
				return -EINVAL;
			opt->keymod_len = keymod_len;
			break;

		case Opt_cover:
			for (cover = AES_ECB; cover < UNKNOWN; cover++) {
				if (0 ==
				    strcmp(args[0].from, key_cover_name[cover]))
					break;
			}
			if (UNKNOWN == cover)
				return -EINVAL;
			opt->cover = cover;
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * datablob_parse - parse the keyctl data and fill in the
 * 		    payload and options structures
 *
 * On success returns 0, otherwise -EINVAL.
 */
static int datablob_parse(char *datablob, struct caam_key_payload *p,
			  struct caam_key_options *o)
{
	substring_t args[MAX_OPT_ARGS];
	long keylen;
	int ret = -EINVAL;
	int key_cmd;
	char *c;

	/* main command */
	c = strsep(&datablob, " \t");
	if (!c)
		return -EINVAL;
	key_cmd = match_token(c, key_tokens, args);
	switch (key_cmd) {
	case Opt_new:
		/* first argument is key size */
		c = strsep(&datablob, " \t");
		if (!c)
			return -EINVAL;
		ret = kstrtol(c, 10, &keylen);
		if (ret < 0 || keylen < MIN_RAWKEY_SIZE
		    || keylen > MAX_RAWKEY_SIZE)
			return -EINVAL;
		p->rawkey_len = keylen;
		ret = getoptions(datablob, p, o);
		if (ret < 0)
			return ret;
		ret = Opt_new;
		break;
	case Opt_load:
		/* first argument is encrypted blob */
		c = strsep(&datablob, " \t");
		if (!c)
			return -EINVAL;
		p->blob_len = strlen(c) / 2;
		if (p->blob_len > MAX_BLOB_SIZE)
			return -EINVAL;
		ret = hex2bin(p->blob, c, p->blob_len);
		if (ret < 0)
			return -EINVAL;
		ret = getoptions(datablob, p, o);
		if (ret < 0)
			return ret;
		ret = Opt_load;
		break;
	case Opt_err:
		return -EINVAL;
		break;
	}

	return ret;
}

static struct caam_key_options *caam_key_options_alloc(void)
{
	struct caam_key_options *options = NULL;

	options = kzalloc(sizeof(*options), GFP_KERNEL);

	if (options) {
		const unsigned int max_keymod_size = MAX_KEYMOD_SIZE;
		options->keymod_len =
		    min(sizeof(def_keymod) / sizeof(def_keymod[0]),
			max_keymod_size);
		memcpy(options->keymod, def_keymod, options->keymod_len);
	}

	return options;
}

static struct caam_key_payload *caam_key_payload_alloc(struct key *key)
{
	struct caam_key_payload *payload = NULL;

	const int ret = key_payload_reserve(key, sizeof(*payload));
	if (ret < 0)
		return NULL;

	payload = kzalloc(sizeof(*payload), GFP_KERNEL);

	return payload;
}

/*
 * get secure memory CAAM device node
 */
static struct device_node *get_sm_dev_node(void)
{
	/* get device node */
	struct device_node *dev_node =
	    of_find_compatible_node(NULL, NULL, "fsl,sec-v4.0");
	if (!dev_node) {
		dev_node = of_find_compatible_node(NULL, NULL, "fsl,sec4.0");
		if (!dev_node) {
			pr_info
			    ("caam_key: no secure memory device node found\n");
			return NULL;
		}
	}

	return dev_node;
}

/*
 * allocate slot for key in CAAM
 *
 * retuns 0, device and allocated slot on success else error
 */
static int allocate_slot(u32 unit, u32 slot_size, struct device **dev,
			 u32 * slot)
{
	int ret = 0;
	u32 units;
	struct device_node *dev_node;
	struct platform_device *pdev;
	struct device *ctrldev;
	struct caam_drv_private *ctrlpriv;

	dev_node = get_sm_dev_node();
	if (NULL == dev_node) {
		return -ENODEV;
	}

	pdev = of_find_device_by_node(dev_node);
	if (!pdev) {
		pr_info("caam_key: no secure memory device found\n");
		return -ENODEV;
	}

	ctrldev = &pdev->dev;
	ctrlpriv = dev_get_drvdata(ctrldev);
	*dev = ctrlpriv->smdev;

	/* check what keystores are available */
	units = sm_detect_keystore_units(*dev);
	if (!units)
		pr_info("caam_key: no keystore units found\n");

	/* check if configured unit is available */
	if (unit >= units) {
		pr_info("caam_key: keystore unit (%d) is not available\n",
			unit);
		return -ENODEV;
	}

	/* initialize keystore */
	ret = sm_establish_keystore(*dev, unit);
	if (ret) {
		pr_info("caam_key: failed to initialize keystore\n");
		return ret;
	}

	/* allocate slot for key */
	ret = sm_keystore_slot_alloc(*dev, unit, slot_size, slot);
	if (ret) {
		pr_info("caam_key: failed to allocate slot for key\n");
		return ret;
	}

	return ret;
}

/*
 * deallocate slot for key in CAAM
 *
 * retuns 0 on success else error
 */
static int deallocate_slot(struct device *dev, u32 unit, u32 slot)
{
	int ret = sm_keystore_slot_dealloc(dev, unit, slot);

	if (0 != ret) {
		pr_info
		    ("caam_key: failed to deallocate slot for key in slot (%d)\n",
		     slot);
	}

	return ret;
}

/*
 * encrypt the symmetric key with CAAM
 */
static int key_encrypt(struct caam_key_payload *p, struct caam_key_options *o)
{
	int ret = -EINVAL;
	struct device *ksdev;
	u32 keyslot;
	/* pad to next larger AES blocksize for blackening of keys to have enough space */
	u32 keyslot_size =
	    (p->color ==
	     RED_KEY ? p->rawkey_len : AES_BLOCK_PAD(p->rawkey_len));

	/* allocate slot for key */
	ret =
	    allocate_slot(CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
			  keyslot_size, &ksdev, &keyslot);
	if (ret) {
		return ret;
	}

	/* load key to allocated slot */
	ret =
	    sm_keystore_slot_load(ksdev,
				  CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
				  keyslot, p->rawkey, p->rawkey_len);
	if (ret) {
		pr_info("caam_key: failed to load key to slot (%d)\n", keyslot);
		goto cleanup;
	}

	if (BLACK_KEY == p->color) {
		/* blacken key */
		ret =
		    sm_keystore_cover_key(ksdev,
					  CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
					  keyslot, p->rawkey_len, o->cover);
		if (ret) {
			pr_info("caam_key: failed to blacken key\n");
			goto cleanup;
		}
	}

	/* encrypt key to blob */
	ret =
	    sm_keystore_slot_export(ksdev,
				    CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
				    keyslot, p->color, o->cover, p->blob,
				    p->rawkey_len, o->keymod);
	if (ret) {
		pr_info("caam_key: failed to export/encrypt key to blob\n");
		goto cleanup;
	}

	p->blob_len = p->rawkey_len + BLOB_OVERHEAD;

 cleanup:
	deallocate_slot(ksdev, CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
			keyslot);

	return ret;
}

/*
 * decrypt the symmetric key with CAAM
 */
static int key_decrypt(struct caam_key_payload *p, struct caam_key_options *o)
{
	int ret = -EINVAL;
	struct device *ksdev;
	u32 keyslot;
	u32 keyslot_size = p->blob_len - BLOB_OVERHEAD;

	/* allocate slot for key */
	ret =
	    allocate_slot(CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
			  keyslot_size, &ksdev, &keyslot);
	if (ret) {
		return ret;
	}

	/* decrypt key to slot */
	ret =
	    sm_keystore_slot_import(ksdev,
				    CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
				    keyslot, p->color, o->cover, p->blob,
				    keyslot_size, o->keymod);
	if (ret) {
		pr_info("caam_key: failed to import/decrypt key to slot (%d)\n",
			keyslot);
		goto cleanup;
	}

	/* read key from slot */
	ret =
	    sm_keystore_slot_read(ksdev,
				  CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
				  keyslot, keyslot_size, p->rawkey);
	if (ret) {
		pr_info("caam_key: failed to read key from slot (%d)\n",
			keyslot);
		goto cleanup;
	}

	p->rawkey_len = keyslot_size;

 cleanup:
	deallocate_slot(ksdev, CONFIG_CRYPTO_DEV_FSL_CAAM_KEY_USED_UNIT,
			keyslot);

	return ret;
}

/*
 * caam_key_instantiate - create a new caam key
 *
 * Decrypt an existing caam blob or, for a new key, get a
 * random key, then encrypt and create a caam key-type key,
 * adding it to the specified keyring.
 *
 * On success, return 0. Otherwise return errno.
 */
static int caam_key_instantiate(struct key *key,
				struct key_preparsed_payload *prep)
{
	struct caam_key_payload *payload = NULL;
	struct caam_key_options *options = NULL;
	const size_t datalen = prep->datalen;
	char *datablob;
	int ret = 0;
	int key_cmd;

	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	datablob = kmalloc(datalen + 1, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;
	memcpy(datablob, prep->data, datalen);
	datablob[datalen] = '\0';

	options = caam_key_options_alloc();
	if (!options) {
		ret = -ENOMEM;
		goto out;
	}

	payload = caam_key_payload_alloc(key);
	if (!payload) {
		ret = -ENOMEM;
		goto out;
	}

	key_cmd = datablob_parse(datablob, payload, options);
	if (key_cmd < 0) {
		ret = key_cmd;
		goto out;
	}

	dump_payload(payload);
	dump_options(options);

	switch (key_cmd) {
	case Opt_load:
		ret = key_decrypt(payload, options);
		if (ret < 0)
			pr_info("caam_key: key_decrypt failed (%d)\n", ret);
		break;
	case Opt_new:
		get_random_bytes(payload->rawkey, payload->rawkey_len);
		ret = key_encrypt(payload, options);
		if (ret < 0)
			pr_info("caam_key: key_encrypt failed (%d)\n", ret);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	dump_payload(payload);
	dump_options(options);

 out:
	kfree(datablob);
	kfree(options);
	if (!ret)
		rcu_assign_keypointer(key, payload);
	else
		kfree(payload);
	return ret;
}

/*
 * caam_key_read - copy the encrypted blob data to userspace in hex.
 * On success, return to userspace the encrypted key datablob size.
 */
static long caam_key_read(const struct key *key, char __user * buffer,
			  size_t buflen)
{
	struct caam_key_payload *p;
	char *ascii_buf;
	char *bufp;
	int i;

	p = rcu_dereference_key(key);
	if (!p)
		return -EINVAL;
	if (!buffer || buflen <= 0)
		return 2 * p->blob_len;
	ascii_buf = kmalloc(2 * p->blob_len, GFP_KERNEL);
	if (!ascii_buf)
		return -ENOMEM;

	bufp = ascii_buf;
	for (i = 0; i < p->blob_len; i++)
		bufp = hex_byte_pack(bufp, p->blob[i]);
	if ((copy_to_user(buffer, ascii_buf, 2 * p->blob_len)) != 0) {
		kfree(ascii_buf);
		return -EFAULT;
	}
	kfree(ascii_buf);
	return 2 * p->blob_len;
}

/*
 * caam_key_destroy - before freeing the key, clear the decrypted data
 */
static void caam_key_destroy(struct key *key)
{
	struct caam_key_payload *p = key->payload.data[0];

	if (!p)
		return;
	memset(p->rawkey, 0, p->rawkey_len);
	kfree(key->payload.data[0]);
}

struct key_type key_type_caam = {
	.name = "caam",
	.instantiate = caam_key_instantiate,
	.destroy = caam_key_destroy,
	.describe = user_describe,
	.read = caam_key_read,
};

EXPORT_SYMBOL_GPL(key_type_caam);

static int __init init_caam_key(void)
{
	struct device_node *dev_node;

	dev_node = get_sm_dev_node();
	if (NULL == dev_node) {
		pr_info("caam_key: no secure memory device node found\n");
		return -ENODEV;
	}
	of_node_get(dev_node);

	return register_key_type(&key_type_caam);
}

static void __exit cleanup_caam_key(void)
{
	struct device_node *dev_node;

	dev_node = get_sm_dev_node();
	if (NULL != dev_node) {
		of_node_put(dev_node);
	}

	unregister_key_type(&key_type_caam);
}

late_initcall(init_caam_key);
module_exit(cleanup_caam_key);

MODULE_LICENSE("GPL");
