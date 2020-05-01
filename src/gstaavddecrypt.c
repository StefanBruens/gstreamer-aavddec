/* GStreamer ISO MPEG DASH common encryption decryptor
 * Copyright (C) 2020 Stefan Brüns <stefan.bruens@rwth-aachen.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */

#include <openssl/opensslv.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#include <string.h>

#include <gst/gst.h>
#include "gstaavddecrypt.h"

struct _AavdDecryptState {
  volatile gint refcount;
  AES_KEY key;
  unsigned char ivec[16];
};

AavdDecryptState *
gst_aavd_decrypt_new(const guint8 *key, const guint8 *iv)
{
  AavdDecryptState *state;

  g_return_val_if_fail (key != NULL, NULL);
  g_return_val_if_fail (iv != NULL, NULL);

  state = g_slice_new (AavdDecryptState);
  if (!state){
    GST_ERROR ("Failed to allocate AavdDecryptState");
    return NULL;
  }

  AES_set_decrypt_key (key, 128, &state->key);
  memcpy (state->ivec, iv, 16);

  return state;
}

AavdDecryptState*
gst_aavd_decrypt_ref(AavdDecryptState *state)
{
  g_return_val_if_fail (state != NULL, NULL);

  g_atomic_int_inc (&state->refcount);

  return state;
}

void
gst_aavd_decrypt_unref(AavdDecryptState *state)
{
  g_return_if_fail (state != NULL);

  if (g_atomic_int_dec_and_test (&state->refcount)) {
    g_slice_free (AavdDecryptState, state);
  }
}

void
gst_aavd_decrypt_ip(AavdDecryptState *state,
		    unsigned char *data,
		    int length)
{
  // Any remaining bytes in the last AES block are not encrypted
  length = (length / 16) * 16;
  CRYPTO_cbc128_decrypt(data, data, length, &state->key, state->ivec,
                        (block128_f)AES_decrypt);
}

G_DEFINE_BOXED_TYPE (AavdDecryptState, gst_aavd,
		     (GBoxedCopyFunc) gst_aavd_decrypt_ref,
		     (GBoxedFreeFunc) gst_aavd_decrypt_unref);
