#ifndef __FASTLZ_COMMON_H__
#define __FASTLZ_COMMON_H__

#define FASTLZ_HASH_LOG  13
#define FASTLZ_HASH_SIZE (1 << FASTLZ_HASH_LOG)
#define FASTLZ_HASH_MASK  (FASTLZ_HASH_SIZE - 1)

/*
 * Always check for bound when decompressing.
 * Generally it is best to leave it defined.
 */
#define FASTLZ_SAFE

#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
#if defined(_MSC_VER) || defined(__GNUC__)
/* #include <windows.h> */
#pragma warning(disable : 4242)
#pragma warning(disable : 4244)
/* 4214 - nonstandard extension used : bit field types other than int */
#pragma warning(disable : 4214)
#endif
#endif

/*
 * Give hints to the compiler for branch prediction optimization.
 */
#if defined(__GNUC__) && (__GNUC__ > 2)
#define FASTLZ_EXPECT_CONDITIONAL(c)	(__builtin_expect((c), 1))
#define FASTLZ_UNEXPECT_CONDITIONAL(c)	(__builtin_expect((c), 0))
#else
#define FASTLZ_EXPECT_CONDITIONAL(c)	(c)
#define FASTLZ_UNEXPECT_CONDITIONAL(c)	(c)
#endif

/*
 * Use inlined functions for supported systems.
 */
#if defined(__GNUC__) || defined(__DMC__) || defined(__POCC__) ||\
	defined(__WATCOMC__) || defined(__SUNPRO_C)
#define FASTLZ_INLINE inline
#elif defined(__BORLANDC__) || defined(_MSC_VER) || defined(__LCC__)
#define FASTLZ_INLINE __inline
#else
#define FASTLZ_INLINE
#endif

/*
 * Prevent accessing more than 8-bit at once, except on x86 architectures.
 */
#if !defined(FASTLZ_STRICT_ALIGN)
#define FASTLZ_STRICT_ALIGN
#if defined(__i386__) || defined(__386)  /* GNU C, Sun Studio */
#undef FASTLZ_STRICT_ALIGN
#elif defined(__i486__) || defined(__i586__) || defined(__i686__) /* GNU C */
#undef FASTLZ_STRICT_ALIGN
#elif defined(_M_IX86) /* Intel, MSVC */
#undef FASTLZ_STRICT_ALIGN
#elif defined(__386)
#undef FASTLZ_STRICT_ALIGN
#elif defined(_X86_) /* MinGW */
#undef FASTLZ_STRICT_ALIGN
#elif defined(__I86__) /* Digital Mars */
#undef FASTLZ_STRICT_ALIGN
#endif
#endif

/*
 * FIXME: use preprocessor magic to set this on different platforms!
 */

#define MAX_COPY       32
#define MAX_LEN       264  /* 256 + 8 */
#define MAX_DISTANCE 8192

#if !defined(FASTLZ_STRICT_ALIGN)
#define FASTLZ_READU16(p) (*((const unsigned short *)(p)))
#else
#define FASTLZ_READU16(p) ((p)[0] | (p)[1]<<8)
#endif

#define HASH_FUNCTION(v, p) {\
				v = FASTLZ_READU16(p);\
				v ^= FASTLZ_READU16(p + 1)^\
				     (v>>(16 - FASTLZ_HASH_LOG));\
				v &= FASTLZ_HASH_MASK;\
			    }

extern unsigned char sixpack_magic[8];

#define CUDBG_BLOCK_SIZE      (63*1024)
#define CUDBG_CHUNK_BUF_LEN   16
#define CUDBG_MIN_COMPR_LEN   32	/*min data length for applying compression*/

/*
 * Use inlined functions for supported systems.
 */
#if defined(__GNUC__) || defined(__DMC__) || defined(__POCC__) || \
	defined(__WATCOMC__) || defined(__SUNPRO_C)

#elif defined(__BORLANDC__) || defined(_MSC_VER) || defined(__LCC__)
#define inline __inline
#else
#define inline
#endif

/* for Adler-32 checksum algorithm, see RFC 1950 Section 8.2 */

#define ADLER32_BASE 65521

static inline unsigned long update_adler32(unsigned long checksum,
					   const void *buf, int len)
{
	const unsigned char *ptr = (const unsigned char *)buf;
	unsigned long s1 = checksum & 0xffff;
	unsigned long s2 = (checksum >> 16) & 0xffff;

	while (len > 0) {
		unsigned k = len < 5552 ? len : 5552;
		len -= k;

		while (k >= 8) {
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			s1 += *ptr++; s2 += s1;
			k -= 8;
		}

		while (k-- > 0) {
			s1 += *ptr++; s2 += s1;
		}
		s1 = s1 % ADLER32_BASE;
		s2 = s2 % ADLER32_BASE;
	}
	return (s2 << 16) + s1;
}
#endif /* __FASTLZ_COMMON_H__ */
