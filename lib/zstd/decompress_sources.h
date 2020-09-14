/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * This file includes every .c file needed for decompression.
 * It is used by lib/decompress_unzstd.c to include the decompression
 * source into the translation-unit, so it can be used for kernel
 * decompression.
 */

#include "entropy_common.c"
#include "fse_decompress.c"
#include "huf_decompress.c"
#include "zstd_common.c"
#include "decompress.c"
