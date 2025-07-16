
#ifndef __CXGB4_OSDEP_H
#define __CXGB4_OSDEP_H

#ifndef fallthrough
#define fallthrough do {} while (0)
#endif

#ifndef strcat_s
#define strcat_s(dst, dst_size, src) strcat(dst, src)
#endif

#ifndef strcpy_s
#define strcpy_s(dst, dst_size, src) strcpy(dst, src)
#endif

#ifndef strncpy_s
#define strncpy_s(dst, dst_size, src, count) strncpy(dst, src, count)
#endif


#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
#define memcpy_s( p_dest, count, p_src, count1)           \
				do {								      \
                 ASSERT(count >= count1)    ;              \
                 RtlCopyMemory(p_dest, p_src, count1);    \
				} while (0)                               //Use the universal api instead of  CRT
#endif              
 

#endif  /* !__CXGB4_OSDEP_H */

