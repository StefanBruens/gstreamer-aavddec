/* GStreamer AAX decryption
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
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef _GST_AAVD_AES_CBC_H_
#define _GST_AAVD_AES_CBC_H_

#include <glib.h>

G_BEGIN_DECLS

typedef struct _AavdDecryptState AavdDecryptState;

AavdDecryptState * gst_aavd_decrypt_new(const unsigned char *key, const unsigned char *iv);
AavdDecryptState * gst_aavd_decrypt_ref(AavdDecryptState *state);
void gst_aavd_decrypt_unref(AavdDecryptState *state);

void gst_aavd_decrypt_ip(AavdDecryptState *state,
			 unsigned char *data,
			 int length);

G_END_DECLS
#endif
