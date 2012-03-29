#ifndef __NET_XFRM_WRAPPER_H
#define __NET_XFRM_WRAPPER_H 1

#include_next <net/xfrm.h>

#ifndef XFRM_PROTO_ESP
#define XFRM_PROTO_ESP		50
#endif

#ifndef XFRM_PROTO_AH
#define XFRM_PROTO_AH		51
#endif

#endif
