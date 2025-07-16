#ifndef __CHELSIO_CXGB4_OCQP_H__
#define __CHELSIO_CXGB4_OCQP_H__

#include "common.h"

u32 cxgb4_uld_ocqp_pool_alloc(struct net_device *dev, int size);
void cxgb4_uld_ocqp_pool_free(struct net_device *dev, u32 addr, int size);
int cxgb4_ocqp_pool_create(struct adapter *adap);
void cxgb4_ocqp_pool_destroy(struct adapter *adap);
#endif
