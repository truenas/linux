/*
   FastLZ - lightning-fast lossless compression library

   Copyright (C) 2007 Ariya Hidayat (ariya@kde.org)
   Copyright (C) 2006 Ariya Hidayat (ariya@kde.org)
   Copyright (C) 2005 Ariya Hidayat (ariya@kde.org)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
   */

#include <fastlz_common.h>

#if !defined(FASTLZ_COMPRESSOR)

#undef FASTLZ_LEVEL
#define FASTLZ_LEVEL 1

#undef FASTLZ_COMPRESSOR
#define FASTLZ_COMPRESSOR fastlz1_compress
static FASTLZ_INLINE int FASTLZ_COMPRESSOR(unsigned char *hash_table,
					   const void *input, int length,
					   void *output);
#include "fastlz.c"

#undef FASTLZ_LEVEL
#define FASTLZ_LEVEL 2

#undef MAX_DISTANCE
#define MAX_DISTANCE 8191
#define MAX_FARDISTANCE (65535 + MAX_DISTANCE - 1)

#undef FASTLZ_COMPRESSOR
#define FASTLZ_COMPRESSOR fastlz2_compress
static FASTLZ_INLINE int FASTLZ_COMPRESSOR(unsigned char *hash_table,
					   const void *input, int length,
					   void *output);
#include "fastlz.c"
int fastlz_compress(unsigned char *hash_table, const void *input, int length,
		    void *output);

int fastlz_compress_level(unsigned char *hash_table, int level,
			  const void *input, int length,
			  void *output);

int fastlz_compress(unsigned char *hash_table, const void *input, int length,
		    void *output)
{
	/* for short block, choose fastlz1 */
	if (length < 65536)
		return fastlz1_compress(hash_table, input, length, output);

	/* else... */
	return fastlz2_compress(hash_table, input, length, output);
}

int fastlz_compress_level(unsigned char *hash_table, int level,
			  const void *input, int length,
			  void *output)
{
	if (level == 1)
		return fastlz1_compress(hash_table, input, length, output);
	if (level == 2)
		return fastlz2_compress(hash_table, input, length, output);

	return 0;
}

#else /* !defined(FASTLZ_COMPRESSOR) */

static FASTLZ_INLINE int FASTLZ_COMPRESSOR(unsigned char *hash_table,
					   const void *input, int length,
					   void *output)
{
	const unsigned char *ip = (const unsigned char *) input;
	const unsigned char *ip_bound = ip + length - 2;
	const unsigned char *ip_limit = ip + length - 12;
	unsigned char *op = (unsigned char *) output;

	const unsigned char **htab = (const unsigned char **)hash_table;
	const unsigned char **hslot;
	unsigned int hval;

	unsigned int copy;

	/* sanity check */
	if (FASTLZ_UNEXPECT_CONDITIONAL(length < 4)) {
		if (length) {
			/* create literal copy only */
			*op++ = length - 1;
			ip_bound++;
			while (ip <= ip_bound)
				*op++ = *ip++;
			return length + 1;
		} else
			return 0;
	}

	/* initializes hash table */
	for (hslot = htab; hslot < htab + FASTLZ_HASH_SIZE; hslot++)
		*hslot = ip;

	/* we start with literal copy */
	copy = 2;
	*op++ = MAX_COPY - 1;
	*op++ = *ip++;
	*op++ = *ip++;

	/* main loop */
	while (FASTLZ_EXPECT_CONDITIONAL(ip < ip_limit)) {
		const unsigned char *ref;
		unsigned int distance;

		/* minimum match length */
		unsigned int len = 3;

		/* comparison starting-point */
		const unsigned char *anchor = ip;

		if (!anchor)
			return 0;

		/* check for a run */
#if FASTLZ_LEVEL == 2
		if (ip[0] == ip[-1] &&
		    FASTLZ_READU16(ip - 1) == FASTLZ_READU16(ip + 1)) {
			distance = 1;
			ip += 3;
			ref = anchor - 1 + 3;
			goto match;
		}
#endif

		/* find potential match */
		HASH_FUNCTION(hval, ip);
		hslot = htab + hval;
		ref = htab[hval];

		/* calculate distance to the match */
		distance = anchor - ref;

		/* update hash table */
		*hslot = anchor;

		if (!ref)
			goto literal;
		/* is this a match? check the first 3 bytes */
		if (distance == 0 ||
#if FASTLZ_LEVEL == 1
				(distance >= MAX_DISTANCE) ||
#else
				(distance >= MAX_FARDISTANCE) ||
#endif
				*ref++ != *ip++ || *ref++ != *ip++ ||
				*ref++ != *ip++)
			goto literal;

#if FASTLZ_LEVEL == 2
		/* far, needs at least 5-byte match */
		if (distance >= MAX_DISTANCE) {
			if (*ip++ != *ref++ || *ip++ != *ref++)
				goto literal;
			len += 2;
		}

match:
#endif

		/* last matched byte */
		ip = anchor + len;

		/* distance is biased */
		distance--;

		if (!distance) {
			/* zero distance means a run */
			unsigned char x = ip[-1];
			while (ip < ip_bound)
				if (*ref++ != x)
					break;
				else
					ip++;
		} else
			for (;;) {
				/* safe because the outer check
				 * against ip limit */
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				if (*ref++ != *ip++)
					break;
				while (ip < ip_bound)
					if (*ref++ != *ip++)
						break;
				break;
			}

		/* if we have copied something, adjust the copy count */
		if (copy)
			/* copy is biased, '0' means 1 byte copy */
			*(op - copy - 1) = copy - 1;
		else
			/* back, to overwrite the copy count */
			op--;

		/* reset literal counter */
		copy = 0;

		/* length is biased, '1' means a match of 3 bytes */
		ip -= 3;
		len = ip - anchor;

		/* encode the match */
#if FASTLZ_LEVEL == 2
		if (distance < MAX_DISTANCE) {
			if (len < 7) {
				*op++ = (len << 5) + (distance >> 8);
				*op++ = (distance & 255);
			} else {
				*op++ = (7 << 5) + (distance >> 8);
				for (len -= 7; len >= 255; len -= 255)
					*op++ = 255;
				*op++ = len;
				*op++ = (distance & 255);
			}
		} else {
			/* far away, but not yet in the another galaxy... */
			if (len < 7) {
				distance -= MAX_DISTANCE;
				*op++ = (len << 5) + 31;
				*op++ = 255;
				*op++ = distance >> 8;
				*op++ = distance & 255;
			} else {
				distance -= MAX_DISTANCE;
				*op++ = (7 << 5) + 31;
				for (len -= 7; len >= 255; len -= 255)
					*op++ = 255;
				*op++ = len;
				*op++ = 255;
				*op++ = distance >> 8;
				*op++ = distance & 255;
			}
		}
#else

		if (FASTLZ_UNEXPECT_CONDITIONAL(len > MAX_LEN - 2))
			while (len > MAX_LEN - 2) {
				*op++ = (7 << 5) + (distance >> 8);
				*op++ = MAX_LEN - 2 - 7 - 2;
				*op++ = (distance & 255);
				len -= MAX_LEN - 2;
			}

		if (len < 7) {
			*op++ = (len << 5) + (distance >> 8);
			*op++ = (distance & 255);
		} else {
			*op++ = (7 << 5) + (distance >> 8);
			*op++ = len - 7;
			*op++ = (distance & 255);
		}
#endif

		/* update the hash at match boundary */
		HASH_FUNCTION(hval, ip);
		htab[hval] = ip++;
		HASH_FUNCTION(hval, ip);
		htab[hval] = ip++;

		/* assuming literal copy */
		*op++ = MAX_COPY - 1;

		continue;

literal:
		*op++ = *anchor++;
		ip = anchor;
		copy++;
		if (FASTLZ_UNEXPECT_CONDITIONAL(copy == MAX_COPY)) {
			copy = 0;
			*op++ = MAX_COPY - 1;
		}
	}

	/* left-over as literal copy */
	ip_bound++;
	while (ip <= ip_bound) {
		*op++ = *ip++;
		copy++;
		if (copy == MAX_COPY) {
			copy = 0;
			*op++ = MAX_COPY - 1;
		}
	}

	/* if we have copied something, adjust the copy length */
	if (copy)
		*(op - copy - 1) = copy - 1;
	else
		op--;

#if FASTLZ_LEVEL == 2
	/* marker for fastlz2 */
	*(unsigned char *)output |= (1 << 5);
#endif

	return op - (unsigned char *)output;
}
#endif /* !defined(FASTLZ_COMPRESSOR) */
