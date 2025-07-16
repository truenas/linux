/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/version.h>

/* RHEL distros has some features from later kernel releases
 * which have been backported. We use these CPP defines to
 * check for these issues ...
 */
#if defined(RHEL_RELEASE_CODE)

  #if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0) && \
      RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0)
    #define RHEL_RELEASE_7_0
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,1)
      #define RHEL_RELEASE_7_1
    #endif
  #endif

  #if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 0) && \
      RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 0)
    #define RHEL_RELEASE_6_0
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 1)
      #define RHEL_RELEASE_6_1
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 2)
      #define RHEL_RELEASE_6_2
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 3)
      #define RHEL_RELEASE_6_3
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 4)
      #define RHEL_RELEASE_6_4
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 5)
      #define RHEL_RELEASE_6_5
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6, 6)
      #define RHEL_RELEASE_6_6
    #endif
  #endif

  #if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 0) && \
      RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5, 0)
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,7)
      #define RHEL_RELEASE_5_7
    #endif
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,9)
      #define RHEL_RELEASE_5_9
    #endif
  #endif

#endif
