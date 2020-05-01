/* GStreamer AAX/AAVD encryption decryptor
 * Copyright (C) 2020 Stefan Brüns <stefan.bruens@rwth-aachen.de>
 *
 * Based on gst-cencdec by Alex Ashley:
 * Copyright (C) 2013 YouView TV Ltd. <alex.ashley@youview.com>
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

/**
 * SECTION:element-gstaavddecrypt
 *
 * Decrypts media that has been encrypted using the proprietary
 * 'aavd' encryption scheme.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>

#include <gst/gst.h>
#include <gst/gstelement.h>
#include <gst/base/gstbasetransform.h>
#include <gst/base/gstbytereader.h>
#include <gst/gstprotection.h>

#include <glib.h>

#include <openssl/sha.h>

#include "gstaavddecrypt.h"

GST_DEBUG_CATEGORY_STATIC (gst_aavd_decrypt_debug_category);
#define GST_CAT_DEFAULT gst_aavd_decrypt_debug_category

#define AUDIBLE_FIXED_KEY "77214d4b196a87cd520045fd20a51d67"
#define FIXED_KEY_LENGTH 16
#define KEY_LENGTH 4

typedef struct _GstAavdKeyPair
{
  GBytes *file_checksum;
  GBytes *key_data;
  unsigned char key[16];
  unsigned char iv[16];
} GstAavdKeyPair;

struct _GstAavdDecrypt
{
  GstBaseTransform parent;
  GPtrArray *keys; /* array of GstAavdKeyPair objects */

  guint8 fixed_key[FIXED_KEY_LENGTH];
};

#define GST_TYPE_AAVD_DECRYPT   (gst_aavd_decrypt_get_type())
G_DECLARE_FINAL_TYPE (GstAavdDecrypt, gst_aavd_decrypt,
    GST, AAVD_DECRYPT, GstBaseTransform)

/* prototypes */
static void gst_aavd_decrypt_dispose (GObject * object);
static void gst_aavd_decrypt_finalize (GObject * object);

static gboolean gst_aavd_decrypt_start (GstBaseTransform * trans);
static gboolean gst_aavd_decrypt_stop (GstBaseTransform * trans);
static void gst_aavd_decrypt_append_if_not_duplicate(GstCaps *dest, GstStructure *new_struct);
static GstCaps *gst_aavd_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter);

static GstFlowReturn gst_aavd_decrypt_transform_ip (GstBaseTransform * trans,
    GstBuffer * buf);
static GstAavdKeyPair* gst_aavd_decrypt_lookup_key (GstAavdDecrypt * self, GstBuffer * data);
static GstAavdKeyPair* gst_aavd_decrypt_get_key (GstAavdDecrypt * self, GstBuffer * data);
static gboolean gst_aavd_decrypt_sink_event_handler (GstBaseTransform * trans,
    GstEvent * event);

/* pad templates */
static GstStaticPadTemplate gst_aavd_decrypt_sink_template =
    GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS
    (
     "application/x-aavd" )
    );

static GstStaticPadTemplate gst_aavd_decrypt_src_template =
    GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY
    );

/* class initialization */
#define gst_aavd_decrypt_parent_class parent_class
G_DEFINE_TYPE (GstAavdDecrypt, gst_aavd_decrypt, GST_TYPE_BASE_TRANSFORM);

static void gst_aavd_keypair_destroy (gpointer data)
{
  GstAavdKeyPair *key_pair = (GstAavdKeyPair*)data;
  g_bytes_unref (key_pair->key_data);
  g_bytes_unref (key_pair->file_checksum);
  g_free (key_pair);
}

static void
gst_aavd_decrypt_class_init (GstAavdDecryptClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstBaseTransformClass *base_transform_class =
      GST_BASE_TRANSFORM_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_aavd_decrypt_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_aavd_decrypt_src_template));

  gst_element_class_set_static_metadata (element_class,
      "Decrypt AAX Audio Streams",
      GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
      "Decrypts Audible AAX encrypted audio streams.",
      "Stefan Brüns <stefan.bruens@rwth-aachen.de>");

  GST_DEBUG_CATEGORY_INIT (gst_aavd_decrypt_debug_category,
      "aavddec", 0, "AAVD decryptor");

  gobject_class->dispose = gst_aavd_decrypt_dispose;
  gobject_class->finalize = gst_aavd_decrypt_finalize;
  base_transform_class->start = GST_DEBUG_FUNCPTR (gst_aavd_decrypt_start);
  base_transform_class->stop = GST_DEBUG_FUNCPTR (gst_aavd_decrypt_stop);
  base_transform_class->transform_ip =
      GST_DEBUG_FUNCPTR (gst_aavd_decrypt_transform_ip);
  base_transform_class->transform_caps =
      GST_DEBUG_FUNCPTR (gst_aavd_decrypt_transform_caps);
  base_transform_class->sink_event =
      GST_DEBUG_FUNCPTR (gst_aavd_decrypt_sink_event_handler);
  base_transform_class->transform_ip_on_passthrough = FALSE;
}

static void
gst_aavd_decrypt_init (GstAavdDecrypt * self)
{
  GstBaseTransform *base = GST_BASE_TRANSFORM (self);

  GST_PAD_SET_ACCEPT_TEMPLATE (GST_BASE_TRANSFORM_SINK_PAD (self));

  gst_base_transform_set_in_place (base, TRUE);
  gst_base_transform_set_passthrough (base, FALSE);
  gst_base_transform_set_gap_aware (GST_BASE_TRANSFORM (self), FALSE);
  self->keys = g_ptr_array_new_with_free_func (gst_aavd_keypair_destroy);

  const char* key = AUDIBLE_FIXED_KEY;
  for (int i = 0; i < FIXED_KEY_LENGTH; i++) {
    guint8 val;
    sscanf(&key[i * 2], "%2hhx", &val);
    self->fixed_key[i] = val;
  }
}

void
gst_aavd_decrypt_dispose (GObject * object)
{
  GstAavdDecrypt *self = GST_AAVD_DECRYPT (object);

  if (self->keys) {
    g_ptr_array_unref (self->keys);
    self->keys = NULL;
  }

  G_OBJECT_CLASS (parent_class)->dispose (object);
}

void
gst_aavd_decrypt_finalize (GObject * object)
{
  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static gboolean
gst_aavd_decrypt_start (GstBaseTransform * trans)
{
  GstAavdDecrypt *self = GST_AAVD_DECRYPT (trans);
  GST_DEBUG_OBJECT (self, "start");
  return TRUE;
}

static gboolean
gst_aavd_decrypt_stop (GstBaseTransform * trans)
{
  GstAavdDecrypt *self = GST_AAVD_DECRYPT (trans);
  GST_DEBUG_OBJECT (self, "stop");
  return TRUE;
}

/*
  Append new_structure to dest, but only if it does not already exist in res.
  This function takes ownership of new_structure.
*/
static void
gst_aavd_decrypt_append_if_not_duplicate(GstCaps *dest, GstStructure *new_struct)
{
  gint j = gst_caps_get_size (dest) - 1;

  for (; j >= 0; --j) {
    GstStructure *s = gst_caps_get_structure (dest, j);
    if (gst_structure_is_equal (s, new_struct)) {
      gst_structure_free (new_struct);
      return;
    }
  }
  gst_caps_append_structure (dest, new_struct);
}

/* filter out the audio and video related fields from the up-stream caps,
   because they are not relevant to the input caps of this element and
   can cause caps negotiation failures with adaptive bitrate streams */
static void
gst_aavd_remove_codec_fields (GstStructure *gs)
{
  gint j = gst_structure_n_fields (gs) - 1;
  for (; j >= 0; --j) {
    const gchar *field_name;

    field_name = gst_structure_nth_field_name (gs, j);
    GST_TRACE ("Check field \"%s\" for removal", field_name);

    if( g_strcmp0 (field_name, "base-profile") == 0 ||
        g_strcmp0 (field_name, "codec_data") == 0 ||
        g_strcmp0 (field_name, "height") == 0 ||
        g_strcmp0 (field_name, "framerate") == 0 ||
        g_strcmp0 (field_name, "level") == 0 ||
        g_strcmp0 (field_name, "pixel-aspect-ratio") == 0 ||
        g_strcmp0 (field_name, "profile") == 0 ||
        g_strcmp0 (field_name, "rate") == 0 ||
        g_strcmp0 (field_name, "width") == 0 ) {
      gst_structure_remove_field (gs, field_name);
      GST_TRACE ("Removing field %s", field_name);
    }
  }
}

/*
  Given the pad in this direction and the given caps, what caps are allowed on
  the other pad in this element ?
*/
static GstCaps *
gst_aavd_decrypt_transform_caps (GstBaseTransform * base,
    GstPadDirection direction, GstCaps * caps, GstCaps * filter)
{
  GstCaps *res = NULL;
  gint i, j;

  g_return_val_if_fail (direction != GST_PAD_UNKNOWN, NULL);

  GST_DEBUG_OBJECT (base, "direction: %s   caps: %" GST_PTR_FORMAT "   filter:"
      " %" GST_PTR_FORMAT, (direction == GST_PAD_SRC) ? "Src" : "Sink",
      caps, filter);

  if(direction == GST_PAD_SRC && gst_caps_is_any (caps)){
    res = gst_pad_get_pad_template_caps (GST_BASE_TRANSFORM_SINK_PAD (base));
    goto filter;
  }

  res = gst_caps_new_empty ();

  for (i = 0; i < gst_caps_get_size (caps); ++i) {
    GstStructure *in = gst_caps_get_structure (caps, i);
    GstStructure *out = NULL;

    if (direction == GST_PAD_SINK) {
      gint n_fields;

      if (!gst_structure_has_field (in, "original-media-type"))
        continue;

      out = gst_structure_copy (in);
      n_fields = gst_structure_n_fields (in);

      gst_structure_set_name (out,
          gst_structure_get_string (out, "original-media-type"));

      /* filter out the DRM related fields from the down-stream caps */
      for(j=n_fields-1; j>=0; --j){
          const gchar *field_name;

          field_name = gst_structure_nth_field_name (in, j);

          if (g_str_has_prefix(field_name, "original-media-type") ) {
              gst_structure_remove_field (out, field_name);
          }
      }
      gst_aavd_decrypt_append_if_not_duplicate(res, out);
    } else {                    /* GST_PAD_SRC */
      out = gst_structure_copy (in);
      gst_aavd_remove_codec_fields (out);

      /* filter out the audio/video related fields from the down-stream
         caps, because they are not relevant to the input caps of this
         element and they can cause caps negotiation failures with
         adaptive bitrate streams */
      gst_structure_set (out,
                         "original-media-type", G_TYPE_STRING, gst_structure_get_name (in),
                         NULL);
      gst_structure_set_name (out, "application/x-aavd");
      gst_aavd_decrypt_append_if_not_duplicate(res, out);

    }
  }
  if(direction == GST_PAD_SINK && gst_caps_get_size (res)==0){
    gst_caps_unref (res);
    res = gst_caps_new_any ();
  }
 filter:
  if (filter) {
    GstCaps *intersection;

    GST_DEBUG_OBJECT (base, "Using filter caps %" GST_PTR_FORMAT, filter);
    intersection =
      gst_caps_intersect_full (res, filter, GST_CAPS_INTERSECT_FIRST);
    gst_caps_unref (res);
    res = intersection;
  }

  GST_DEBUG_OBJECT (base, "returning %" GST_PTR_FORMAT, res);
  return res;
}

static void
gst_aavd_decrypt_parse_adrm_box (GstAavdDecrypt * self, GstBuffer * adrm)
{
  GstMapInfo info;
  GstByteReader br;
  guint32 version;
  guint32 data_size;
  guint32 dummy;
  GstAavdKeyPair *kp = NULL;

  gst_buffer_map (adrm, &info, GST_MAP_READ);
  gst_byte_reader_init (&br, info.data, info.size);

  GST_DEBUG_OBJECT (self, "adrm size: %" G_GSIZE_FORMAT, info.size);

  gst_byte_reader_skip (&br, 8);
  data_size = gst_byte_reader_get_uint32_be_unchecked (&br);
  version = gst_byte_reader_get_uint32_be_unchecked (&br);

  GST_DEBUG_OBJECT (self, "adrm version: %u", version);
  GST_DEBUG_OBJECT (self, "adrm key data size: %u", data_size);

  if (version != 1) {
    GST_WARNING_OBJECT (self, "Found unexpected adrm version: %d %x", version, version);
  }

  g_return_if_fail (data_size == 0x38);

  kp = g_new0 (GstAavdKeyPair, 1);
  if (data_size > 8U) {
    data_size -= 8;
    gpointer data =
        g_memdup (gst_byte_reader_get_data_unchecked (&br, data_size),
        data_size);
    GBytes *buf = g_bytes_new_take (data, data_size);
    GST_DEBUG_OBJECT (self, "aavd protection system data size: %"
        G_GSIZE_FORMAT, g_bytes_get_size(buf));
    kp->key_data = buf;
  }

  dummy = gst_byte_reader_get_uint32_be_unchecked (&br);
  if (dummy != 0)
    GST_WARNING_OBJECT (self, "Found unexpected value: %d", dummy);

  dummy = gst_byte_reader_get_uint32_be_unchecked (&br);
  if (dummy != 1)
    GST_WARNING_OBJECT (self, "Found unexpected value: %d", dummy);

  dummy = gst_byte_reader_get_uint32_be_unchecked (&br);
  if (dummy != 0)
    GST_WARNING_OBJECT (self, "Found unexpected value: %d", dummy);

  gpointer data =
      g_memdup (gst_byte_reader_get_data_unchecked (&br, 20), 20);
  const guint8* cs = (const guint8*) data;
  GST_INFO_OBJECT (self, "aavd key_checksum: "
      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
      cs[0], cs[1], cs[2], cs[3], cs[4], cs[5], cs[6], cs[7], cs[8],  cs[9],
      cs[10], cs[11], cs[12], cs[13], cs[14], cs[15], cs[16], cs[17], cs[18],  cs[19]);

  GBytes *buf = g_bytes_new_take (data, 20);
  kp->file_checksum = buf;

  gst_buffer_unmap (adrm, &info);

  g_ptr_array_add (self->keys, kp);
}

static GstAavdKeyPair *
gst_aavd_decrypt_get_key (GstAavdDecrypt * self, GstBuffer * data)
{
  char hexkey[KEY_LENGTH * 2] = { 0 };
  guint8 key[KEY_LENGTH];
  gchar *path;
  size_t bytes_read = 0;
  FILE *key_file = NULL;
  GstAavdKeyPair *kp = NULL;
  gconstpointer file_checksum;
  gsize cs_size;

  gst_aavd_decrypt_parse_adrm_box (self, data);

  kp = g_ptr_array_index (self->keys, 0);
  file_checksum = g_bytes_get_data(kp->file_checksum, &cs_size);

  /* Read contents of file with the hash as its name. */
  path = g_strconcat ("/tmp/", "aavd", ".key", NULL);

  GST_DEBUG_OBJECT (self, "Opening file: %s", path);
  key_file = fopen (path, "rb");

  if (!key_file) {
    GST_ERROR_OBJECT (self, "Failed to open keyfile: %s", path);
    goto error;
  }

  bytes_read = fread (hexkey, 1, KEY_LENGTH * 2 + 1, key_file);

  if (bytes_read < KEY_LENGTH * 2) {
    GST_ERROR_OBJECT (self, "Failed to read key from file %s", path);
    fclose (key_file);
    goto error;
  }
  if (bytes_read == KEY_LENGTH * 2 + 1) {
    guint8 terminator = hexkey[KEY_LENGTH * 2];
    if ((terminator != '\n') && (terminator != '\0')) {
      GST_ERROR_OBJECT (self, "Unexpected character '%c' [0x%02x] in keyfile %s", terminator, terminator, path);
      fclose (key_file);
      goto error;
    }
  }

  fclose (key_file);

  for (int i = 0; i < KEY_LENGTH; i++) {
    guint8 val;
    if (sscanf(&hexkey[i * 2], "%2hhx", &val) != 1) {
      GST_ERROR_OBJECT (self, "Unexpected characters '%c%c' [0x%02x %02x] in keyfile %s",
          hexkey[i * 2], hexkey[i * 2 + 1], hexkey[i * 2], hexkey[i * 2 + 1], path);
      goto error;
    }
    key[i] = val;
  }
  GST_INFO_OBJECT (self, "Read key: %02x%02x%02x%02x", key[0], key[1], key[2], key[3]);

  g_free (path);

  if (cs_size == 20) {
    GChecksum *cs;
    guint8 intermediate_key[20];
    guint8 intermediate_iv[20];
    guint8 key_checksum[20];

    cs = g_checksum_new (G_CHECKSUM_SHA1);

    g_checksum_update (cs, self->fixed_key, FIXED_KEY_LENGTH);
    g_checksum_update (cs, key, KEY_LENGTH);
    g_checksum_get_digest (cs, intermediate_key, &cs_size);
    GST_TRACE_OBJECT (self, "Intermediate key: %s", g_checksum_get_string (cs));

    g_checksum_reset (cs);
    g_checksum_update (cs, self->fixed_key, FIXED_KEY_LENGTH);
    g_checksum_update (cs, intermediate_key, 20);
    g_checksum_update (cs, key, KEY_LENGTH);
    g_checksum_get_digest (cs, intermediate_iv, &cs_size);
    GST_TRACE_OBJECT (self, "Intermediate iv: %s", g_checksum_get_string (cs));

    g_checksum_reset (cs);
    g_checksum_update (cs, intermediate_key, 16);
    g_checksum_update (cs, intermediate_iv, 16);
    g_checksum_get_digest (cs, key_checksum, &cs_size);

    if (memcmp(key_checksum, file_checksum, cs_size)) {
      GST_ERROR_OBJECT (self, "Computed checksum: %s", g_checksum_get_string (cs));
      kp = NULL;

    } else {
      AavdDecryptState *state = NULL;

      GST_INFO_OBJECT (self, "Computed checksum: %s", g_checksum_get_string (cs));

      state = gst_aavd_decrypt_new (intermediate_key, intermediate_iv);
      if (state) {
	guint8 data[48];
	memcpy(data, g_bytes_get_data(kp->key_data, NULL), sizeof(data));

	gst_aavd_decrypt_ip (state, data, 48);

	if (data[0] != key[3]) {
          kp = NULL;
	} else {
	  memcpy(kp->key, data + 8, 16);

          g_checksum_reset (cs);
          g_checksum_update (cs, data + 26, 16);
          g_checksum_update (cs, data + 8, 16);
          g_checksum_update (cs, self->fixed_key, FIXED_KEY_LENGTH);
          g_checksum_get_digest (cs, kp->iv, &cs_size);

	  for (int i = 0; i < 16; i += 8) {
            GST_INFO_OBJECT (self, "%02x %02x %02x %02x  %02x %02x %02x %02x\n",
	        kp->iv[i + 0], kp->iv[i + 1], kp->iv[i + 2], kp->iv[i + 3],
	        kp->iv[i + 4], kp->iv[i + 5], kp->iv[i + 6], kp->iv[i + 7]);
	  }
	}
      }
      gst_aavd_decrypt_unref (state);
    }

    g_checksum_free (cs);
  }

  return kp;
error:
  g_free (path);
  return NULL;
}

static GstAavdKeyPair *
gst_aavd_decrypt_lookup_key (GstAavdDecrypt * self, GstBuffer * data)
{
  if (self->keys->len > 0) {
    GstAavdKeyPair *kp = g_ptr_array_index (self->keys, 0);
    if (kp->key) {
      return kp;
    }
    return NULL;
  }
  return gst_aavd_decrypt_get_key (self, data);
}

static GstFlowReturn
gst_aavd_decrypt_transform_ip (GstBaseTransform * base, GstBuffer * buf)
{
  GstAavdDecrypt *self = GST_AAVD_DECRYPT (base);
  GstFlowReturn ret = GST_FLOW_OK;
  GstMapInfo map;
  const GstAavdKeyPair *keypair;
  const GstProtectionMeta *prot_meta = NULL;
  AavdDecryptState *state = NULL;
  gboolean encrypted;
  const GValue *value;
  GstBuffer *adrm_buf = NULL;

  GST_TRACE_OBJECT (self, "decrypt in-place");
  prot_meta = (GstProtectionMeta*) gst_buffer_get_protection_meta (buf);
  if (!prot_meta || !buf) {
    if (!prot_meta) {
      GST_ERROR_OBJECT (self, "Failed to get GstProtection metadata from buffer");
    }
    if (!buf) {
      GST_ERROR_OBJECT (self, "Failed to get writable buffer");
    }
    ret = GST_FLOW_NOT_SUPPORTED;
    goto out;
  }

  if (!gst_buffer_map (buf, &map, GST_MAP_READWRITE)) {
    GST_ERROR_OBJECT (self, "Failed to map buffer");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto release;
  }

  if(!gst_structure_get_boolean(prot_meta->info, "encrypted", &encrypted)){
    GST_ERROR_OBJECT (self, "failed to get encrypted flag");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto beach;
  }
  if (!encrypted) {
    /* sample is not encrypted */
    goto beach;
  }
  GST_TRACE_OBJECT (self, "decrypt %d samples", (gint)map.size);

  value = gst_structure_get_value (prot_meta->info, "adrm");
  if(!value){
    GST_ERROR_OBJECT (self, "Failed to get adrm data");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto beach;
  }
  adrm_buf = gst_value_get_buffer (value);

  keypair = gst_aavd_decrypt_lookup_key (self, adrm_buf);

  if (!keypair) {
    GST_ERROR_OBJECT (self, "Failed to lookup key");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto beach;
  }

  state = gst_aavd_decrypt_new (keypair->key, keypair->iv);

  if (!state) {
    GST_ERROR_OBJECT (self, "Failed to init AES cipher");
    ret = GST_FLOW_NOT_SUPPORTED;
    goto beach;
  }

  gst_aavd_decrypt_ip (state, map.data, map.size);

beach:
  gst_buffer_unmap (buf, &map);
release:
  if (state) {
    gst_aavd_decrypt_unref (state);
  }
out:
  return ret;
}

static void
gst_aavd_decrypt_parse_protection_event (GstEvent * event, GstBuffer ** data)
{
  const GstStructure *s;

  g_return_if_fail (event != NULL);
  g_return_if_fail (GST_IS_EVENT (event));
  g_return_if_fail (GST_EVENT_TYPE (event) == GST_EVENT_PROTECTION);

  s = gst_event_get_structure (event);

  if (data) {
    const GValue *value = gst_structure_get_value (s, "data");
    *data = gst_value_get_buffer (value);
  }
}

static gboolean
gst_aavd_decrypt_sink_event_handler (GstBaseTransform * trans, GstEvent * event)
{
  gboolean ret = TRUE;
  GstBuffer *adrm = NULL;
  GstAavdDecrypt *self = GST_AAVD_DECRYPT (trans);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_PROTECTION:
        GST_DEBUG_OBJECT (self, "received protection event");
        gst_aavd_decrypt_parse_protection_event (event, &adrm);
        gst_aavd_decrypt_parse_adrm_box (self, adrm);
        gst_event_unref (event);
      break;

    default:
      ret = GST_BASE_TRANSFORM_CLASS (parent_class)->sink_event (trans, event);
      break;
  }

  return ret;
}

static gboolean
plugin_init (GstPlugin * plugin)
{
  return gst_element_register (plugin, "aavddec", GST_RANK_PRIMARY,
      GST_TYPE_AAVD_DECRYPT);
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    aavddec,
    "AAX/aavd decryption element",
    plugin_init,
    PACKAGE_VERSION,
    GST_LICENSE,
    GST_PACKAGE_NAME,
    GST_PACKAGE_ORIGIN
);
