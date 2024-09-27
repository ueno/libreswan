/*
 * Copyright (C) 2024 Daiki Ueno <dueno@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stddef.h>
#include <stdint.h>

#include "nspr.h"
#include "pk11pub.h"
#include "keyhi.h"

#include "constants.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswlog.h"

#include "ike_alg.h"
#include "ike_alg_dh_ops.h"
#include "crypt_symkey.h"

static void nss_kem_calc_local_secret(const struct dh_desc *group,
				      SECKEYPrivateKey **privk,
				      SECKEYPublicKey **pubk,
				      struct logger *logger)
{
	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		return;
	}

	*privk = PK11_GenerateKeyPair(slot,
				      group->kem_generation_mechanism,
				      (void *)&group->kem_generation_params,
				      pubk, PR_FALSE, PR_FALSE, NULL);
}

static shunk_t nss_kem_local_secret_ke(const struct dh_desc *group UNUSED,
				       const SECKEYPublicKey *local_pubk)
{
	passert(local_pubk->u.kyber.params == params_kyber768_round3);
	dbg("putting NSS raw Kyber768 public key blob on wire");
	return same_secitem_as_shunk(local_pubk->u.kyber.publicValue);
}

static diag_t nss_kem_encapsulate(const struct dh_desc *group UNUSED,
				  chunk_t remote_ke,
				  PK11SymKey **shared_secret,
				  chunk_t *ciphertext,
				  struct logger *logger)
{
	diag_t d = NULL;

	SECKEYPublicKey remote_pubk = {
		.pkcs11ID = CK_INVALID_HANDLE,
		.keyType = kyberKey,
		.u.kyber.params = params_kyber768_round3,
	};

	if (remote_ke.len != KYBER768_PUBLIC_KEY_BYTES) {
		d = diag("remote public key is too long");
		goto out;
	}

	if (SECITEM_AllocItem(NULL, &remote_pubk.u.kyber.publicValue,
			      remote_ke.len) == NULL) {
		d = diag_nss_error("allocation of Kyber768 public key failed");
	}
	memcpy(remote_pubk.u.kyber.publicValue.data, remote_ke.ptr, remote_ke.len);

	ldbg(logger, "passing raw Kyber768 public key blob to NSS");

	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		d = diag("NSS: could not authenticate slot");
		goto out;
	}

	CK_OBJECT_HANDLE handle = PK11_ImportPublicKey(slot, &remote_pubk, PR_FALSE);
	PK11_FreeSlot(slot);
	if (handle == CK_INVALID_HANDLE) {
		d = diag("could not import public key");
		goto out;
	}

	SECItem *si = NULL;
	SECStatus rv = PK11_Encapsulate(&remote_pubk, CKM_EXTRACT_KEY_FROM_KEY,
					PK11_ATTR_PRIVATE | PK11_ATTR_UNMODIFIABLE,
					CKF_ENCRYPT,
					shared_secret, &si);
	if (rv != SECSuccess) {
		d = diag_nss_error("encapsulation failed");
		goto out;
	}
	replace_chunk_bytes(ciphertext, si->data, si->len, "ciphertext");
	SECITEM_FreeItem(si, PR_TRUE);

 out:
	PK11_DestroyObject(remote_pubk.pkcs11Slot, remote_pubk.pkcs11ID);
	PK11_FreeSlot(remote_pubk.pkcs11Slot);
	SECITEM_FreeItem(&remote_pubk.u.kyber.publicValue, PR_FALSE);
	return d;
}

static diag_t nss_kem_decapsulate(const struct dh_desc *group UNUSED,
				  SECKEYPrivateKey *local_privk,
				  chunk_t remote_ke,
				  PK11SymKey **shared_secret,
				  struct logger *logger)
{
	SECItem ciphertext = same_chunk_as_secitem(remote_ke, siBuffer);
	SECStatus rv = PK11_Decapsulate(local_privk, &ciphertext, CKM_EXTRACT_KEY_FROM_KEY,
					PK11_ATTR_PRIVATE | PK11_ATTR_UNMODIFIABLE,
					CKF_ENCRYPT,
					shared_secret);
	if (rv != SECSuccess) {
		return diag_nss_error("decapsulation failed");
	}
	ldbg(logger, "decapsulating raw Kyber768 shared secret to NSS");
	return NULL;
}

static void nss_kem_check(const struct dh_desc *dhmke, struct logger *logger)
{
	const struct ike_alg *alg = &dhmke->common;
	pexpect_ike_alg(logger, alg, dhmke->kem_mechanism == CKM_NSS_KYBER);
	pexpect_ike_alg(logger, alg, dhmke->kem_generation_mechanism == CKM_NSS_KYBER_KEY_PAIR_GEN);
	pexpect_ike_alg(logger, alg, dhmke->kem_generation_params == CKP_NSS_KYBER_768_ROUND3);
}

const struct dh_ops ike_alg_dh_nss_kem_ops = {
	.backend = "NSS(KEM)",
	.check = nss_kem_check,
	.calc_local_secret = nss_kem_calc_local_secret,
	.local_secret_ke = nss_kem_local_secret_ke,
	.calc_shared_secret = NULL, /* unused */
	.encapsulate = nss_kem_encapsulate,
	.decapsulate = nss_kem_decapsulate,
};
