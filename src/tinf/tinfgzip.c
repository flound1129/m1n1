/*
 * tinfgzip - tiny gzip decompressor
 *
 * Copyright (c) 2003-2019 Joergen Ibsen
 *
 * This version of tinfzlib was modified for use with m1n1.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software. If you use this
 *      software in a product, an acknowledgment in the product
 *      documentation would be appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must
 *      not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *      distribution.
 */

#include "tinf.h"

typedef enum {
	FTEXT    = 1,
	FHCRC    = 2,
	FEXTRA   = 4,
	FNAME    = 8,
	FCOMMENT = 16
} tinf_gzip_flag;

static unsigned int read_le16(const unsigned char *p)
{
	return ((unsigned int) p[0])
	     | ((unsigned int) p[1] << 8);
}

static unsigned int read_le32(const unsigned char *p)
{
	return ((unsigned int) p[0])
	     | ((unsigned int) p[1] << 8)
	     | ((unsigned int) p[2] << 16)
	     | ((unsigned int) p[3] << 24);
}

static int tinf_gzip_uncompress_impl(void *dest, unsigned int *destLen,
                                     const void *source, unsigned int *sourceLen,
                                     int prefix)
{
	const unsigned char *src = (const unsigned char *) source;
	unsigned char *dst = (unsigned char *) dest;
	const unsigned char *start;
	unsigned int dlen, crc32;
	int res;
	unsigned char flg;
	unsigned int sourceDataLen = 0;
	unsigned int sourceCap;
	unsigned int headerLen;
	unsigned int footerOffset;

	if (prefix && (!sourceLen || !*sourceLen))
		return TINF_DATA_ERROR;
	sourceCap = sourceLen ? *sourceLen : 0;

	/* -- Check header -- */

	/* Check room for at least 10 byte header and 8 byte trailer */
	if (*sourceLen && *sourceLen < 18) {
		return TINF_DATA_ERROR;
	}

	/* Check id bytes */
	if (src[0] != 0x1F || src[1] != 0x8B) {
		return TINF_DATA_ERROR;
	}

	/* Check method is deflate */
	if (src[2] != 8) {
		return TINF_DATA_ERROR;
	}

	/* Get flag byte */
	flg = src[3];

	/* Check that reserved bits are zero */
	if (flg & 0xE0) {
		return TINF_DATA_ERROR;
	}

	/* -- Find start of compressed data -- */

	/* Skip base header of 10 bytes */
	start = src + 10;

	/* Skip extra data if present */
	if (flg & FEXTRA) {
		unsigned int xlen = read_le16(start);

		if (*sourceLen && xlen > *sourceLen - 12) {
			return TINF_DATA_ERROR;
		}

		start += xlen + 2;
	}

	/* Skip file name if present */
	if (flg & FNAME) {
		do {
			if (*sourceLen && start - src >= *sourceLen) {
				return TINF_DATA_ERROR;
			}
		} while (*start++);
	}

	/* Skip file comment if present */
	if (flg & FCOMMENT) {
		do {
			if (*sourceLen && start - src >= *sourceLen) {
				return TINF_DATA_ERROR;
			}
		} while (*start++);
	}

	/* Check header crc if present */
	if (flg & FHCRC) {
		unsigned int hcrc;

		if (*sourceLen && start - src > *sourceLen - 2) {
			return TINF_DATA_ERROR;
		}

		hcrc = read_le16(start);

		if (hcrc != (tinf_crc32(src, start - src) & 0x0000FFFF)) {
			return TINF_DATA_ERROR;
		}

		start += 2;
	}

	/* -- Get decompressed length if an exact source length is available -- */

	if (!prefix && *sourceLen) {
		dlen = read_le32(&src[*sourceLen - 4]);

		if (dlen > *destLen) {
			return TINF_BUF_ERROR;
		}
	}

	/* -- Check source length if available -- */

	if (!prefix && *sourceLen) {
		if ((src + *sourceLen) - start < 8) {
			return TINF_DATA_ERROR;
		}
		sourceDataLen = (src + *sourceLen) - start - 8;
	} else if (prefix) {
		headerLen = (unsigned int)(start - src);
		if (headerLen > sourceCap || sourceCap - headerLen < 8)
			return TINF_DATA_ERROR;
		sourceDataLen = sourceCap - headerLen - 8;
	}

	/* -- Decompress data -- */

	if (prefix)
		res = tinf_uncompress_prefix(dst, destLen, start, &sourceDataLen);
	else
		res = tinf_uncompress(dst, destLen, start, &sourceDataLen);

	if (res != TINF_OK) {
		return TINF_DATA_ERROR;
	}

	if (prefix) {
		headerLen = (unsigned int)(start - src);
		if (sourceDataLen > sourceCap - headerLen - 8)
			return TINF_DATA_ERROR;
		footerOffset = headerLen + sourceDataLen;
		if (footerOffset > sourceCap - 8)
			return TINF_DATA_ERROR;
		*sourceLen = footerOffset + 8;
		dlen = read_le32(&src[footerOffset + 4]);
		crc32 = read_le32(&src[footerOffset]);
	} else {
		sourceDataLen += (start - src) + 8;

		if (*sourceLen && *sourceLen != sourceDataLen) {
			return TINF_DATA_ERROR;
		}

		*sourceLen = sourceDataLen;

		/* -- Check decompressed length -- */

		dlen = read_le32(&src[*sourceLen - 4]);
		crc32 = read_le32(&src[*sourceLen - 8]);
	}

	if (*destLen != dlen) {
		return TINF_DATA_ERROR;
	}

	/* -- Check CRC32 checksum -- */

	if (crc32 != tinf_crc32(dst, dlen)) {
		return TINF_DATA_ERROR;
	}

	return TINF_OK;
}

/* Historical exact-length/sentinel API. */
int tinf_gzip_uncompress(void *dest, unsigned int *destLen,
                         const void *source, unsigned int *sourceLen)
{
	return tinf_gzip_uncompress_impl(dest, destLen, source, sourceLen, 0);
}

/* Bounded prefix API: consume one gzip member at the beginning of a finite
 * buffer and return its actual total length, leaving any suffix untouched. */
int tinf_gzip_uncompress_prefix(void *dest, unsigned int *destLen,
                                const void *source, unsigned int *sourceLen)
{
	return tinf_gzip_uncompress_impl(dest, destLen, source, sourceLen, 1);
}
