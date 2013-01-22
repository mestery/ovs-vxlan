/*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"

#define LISP_DST_PORT 4341  /* Well known UDP port for LISP data packets. */

struct lisp_net {
	struct socket *lisp_rcv_socket;
	int n_tunnels;
};
static struct lisp_net lisp_net;


/*
 *  LISP encapsulation header:
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |N|L|E|V|I|flags|            Nonce/Map-Version                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Instance ID/Locator Status Bits               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/**
 * struct lisphdr - LISP header
 * @nonce_present: Flag indicating the presence of a 24 bit nonce value.
 * @lsb: Flag indicating the presence of Locator Status Bits (LSB).
 * @echo_nonce: Flag indicating the use of the echo noncing mechanism.
 * @map_version: Flag indicating the use of mapping versioning.
 * @instance_id: Flag indicating the presence of a 24 bit Instance ID (IID).
 * @rflags: 3 bits reserved for future flags.
 * @nonce: 24 bit nonce value.
 * @lsb_bits: 32 bit Locator Status Bits
 */
struct lisphdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 rflags:3;
	__u8 instance_id:1;
	__u8 map_version:1;
	__u8 echo_nonce:1;
	__u8 lsb:1;
	__u8 nonce_present:1;
#else
	__u8 nonce_present:1;
	__u8 lsb:1;
	__u8 echo_nonce:1;
	__u8 map_version:1;
	__u8 instance_id:1;
	__u8 rflags:3;
#endif
	union {
		__u8 nonce[3];
		__u8 map_version[3];
	} u1;
	union {
		__be32 lsb_bits;
		__be32 iid;
	} u2;
};

#define LISP_HLEN (sizeof(struct udphdr) + sizeof(struct lisphdr))

static inline int lisp_hdr_len(const struct tnl_mutable_config *mutable,
			       const struct ovs_key_ipv4_tunnel *tun_key)
{
	return LISP_HLEN;
}

static inline struct lisphdr *lisp_hdr(const struct sk_buff *skb)
{
	return (struct lisphdr *)(udp_hdr(skb) + 1);
}

/* Compute source port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct sk_buff *skb)
{
	int low;
	int high;
	unsigned int range;
	u32 hash = OVS_CB(skb)->flow->hash;

	inet_get_local_port_range(&low, &high);
	range = (high - low) + 1;
	return (((u64) hash * range) >> 32) + low;
}

static struct sk_buff *lisp_pre_tunnel(const struct vport *vport,
				       const struct tnl_mutable_config *mutable,
				       struct sk_buff *skb)
{
	/* Pop off "inner" Ethernet header */
	skb_pull(skb, ETH_HLEN);
	return skb;
}

/* Returns the least-significant 32 bits of a __be64. */
static __be32 be64_get_low32(__be64 x)
{
#ifdef __BIG_ENDIAN
	return (__force __be32)x;
#else
	return (__force __be32)((__force u64)x >> 32);
#endif
}

static struct sk_buff *lisp_build_header(const struct vport *vport,
					 const struct tnl_mutable_config *mutable,
					 struct dst_entry *dst,
					 struct sk_buff *skb,
					 int tunnel_hlen)
{
	struct udphdr *udph = udp_hdr(skb);
	struct lisphdr *lisph = (struct lisphdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
	__be64 out_key;
	u32 flags;

	tnl_get_param(mutable, tun_key, &flags, &out_key);

	udph->dest = htons(LISP_DST_PORT);
	udph->source = htons(get_src_port(skb));
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	lisph->nonce_present = 1;   /* We add a nonce instead of map version */
	lisph->lsb = 0;		    /* No reason to set LSBs, just one RLOC */
	lisph->echo_nonce = 0;	    /* No echo noncing */
	lisph->map_version = 0;	    /* No mapping versioning, nonce instead */
	lisph->instance_id = 1;	    /* Store the tun_id as Instance ID  */
	lisph->rflags = 1;	    /* Reserved flags, set to 0  */

	lisph->u1.nonce[0] = net_random() & 0xFF;
	lisph->u1.nonce[1] = net_random() & 0xFF;
	lisph->u1.nonce[2] = net_random() & 0xFF;

	lisph->u2.iid = htonl(be64_get_low32(tun_key->tun_id));

	/*
	 * Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort.  We also need to force selection of
	 * an IP ID here because Linux will otherwise leave it at 0 if the
	 * packet originally had DF set.
	 */
	skb->local_df = 1;
	__ip_select_ident(ip_hdr(skb), dst, 0);

	return skb;
}

/* Called with rcu_read_lock and BH disabled. */
static int lisp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct lisphdr *lisph;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;
	struct ovs_key_ipv4_tunnel tun_key;
	__be64 key;
	u32 tunnel_flags = 0;
	struct ethhdr *ethh;

	if (unlikely(!pskb_may_pull(skb, LISP_HLEN)))
		goto error;

	lisph = lisp_hdr(skb);
	if (unlikely(lisph->instance_id != 1))
		goto error;

	__skb_pull(skb, LISP_HLEN);
	skb_postpull_rcsum(skb, skb_transport_header(skb), LISP_HLEN);

	key = cpu_to_be64(ntohl(lisph->u2.iid));

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(dev_net(skb->dev), iph->daddr, iph->saddr,
				  key, TNL_T_PROTO_LISP, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	if (mutable->flags & TNL_F_IN_KEY_MATCH || !mutable->key.daddr)
		tunnel_flags = OVS_TNL_F_KEY;
	else
		key = 0;

	/* Save outer tunnel values */
	tnl_tun_key_init(&tun_key, iph, key, tunnel_flags);
	OVS_CB(skb)->tun_key = &tun_key;

	/* Add Ethernet header */
	skb_push(skb, ETH_HLEN);

	ethh = (struct ethhdr *)skb->data;
	memset(ethh, 0, ETH_HLEN);
	ethh->h_dest[0] = 0x02;
	ethh->h_source[0] = 0x02;
	ethh->h_proto = htons(ETH_P_IP);

	ovs_tnl_rcv(vport, skb);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

/* Arbitrary value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_LISP 7
static int lisp_socket_init(struct net *net)
{
	int err;
	struct sockaddr_in sin;

	if (lisp_net.n_tunnels) {
		lisp_net.n_tunnels++;
		return 0;
	}

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &lisp_net.lisp_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(lisp_net.lisp_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(LISP_DST_PORT);

	err = kernel_bind(lisp_net.lisp_rcv_socket,
			  (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(lisp_net.lisp_rcv_socket->sk)->encap_type = UDP_ENCAP_LISP;
	udp_sk(lisp_net.lisp_rcv_socket->sk)->encap_rcv = lisp_rcv;

	udp_encap_enable();
	lisp_net.n_tunnels++;

	return 0;

error_sock:
	sk_release_kernel(lisp_net.lisp_rcv_socket->sk);
error:
	pr_warn("cannot register lisp protocol handler: %d\n", err);
	return err;
}

static const struct tnl_ops ovs_lisp_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_LISP,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= lisp_hdr_len,
	.pre_tunnel	= lisp_pre_tunnel,
	.build_header	= lisp_build_header,
};

static void release_socket(struct net *net)
{
	lisp_net.n_tunnels--;
	if (lisp_net.n_tunnels)
		return;

	sk_release_kernel(lisp_net.lisp_rcv_socket->sk);
}

static void lisp_tnl_destroy(struct vport *vport)
{
	ovs_tnl_destroy(vport);
	release_socket(ovs_dp_get_net(vport->dp));
}

static struct vport *lisp_tnl_create(const struct vport_parms *parms)
{
	int err;
	struct vport *vport;

	err = lisp_socket_init(ovs_dp_get_net(parms->dp));
	if (err)
		return ERR_PTR(err);

	vport = ovs_tnl_create(parms, &ovs_lisp_vport_ops, &ovs_lisp_tnl_ops);
	if (IS_ERR(vport))
		release_socket(ovs_dp_get_net(parms->dp));

	return vport;
}

static int lisp_tnl_init(void)
{
	lisp_net.n_tunnels = 0;
	return 0;
}

const struct vport_ops ovs_lisp_vport_ops = {
	.type		= OVS_VPORT_TYPE_LISP,
	.flags		= VPORT_F_TUN_ID,
	.init		= lisp_tnl_init,
	.create		= lisp_tnl_create,
	.destroy	= lisp_tnl_destroy,
	.set_addr	= ovs_tnl_set_addr,
	.get_name	= ovs_tnl_get_name,
	.get_addr	= ovs_tnl_get_addr,
	.get_options	= ovs_tnl_get_options,
	.set_options	= ovs_tnl_set_options,
	.send		= ovs_tnl_send,
};
#else
#warning LISP tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
