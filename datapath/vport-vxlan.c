 /*
 * Copyright (c) 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

#define VXLAN_DST_PORT 4341
#define VXLAN_IPSEC_SRC_PORT 4564

#define VXLAN_FLAGS 0x08000000  /* struct vxlanhdr.vx_flags required value. */

/**
 * struct vxlanhdr - VXLAN header
 * @vx_flags: Must have the exact value %VXLAN_FLAGS.
 * @vx_vni: VXLAN Network Identifier (VNI) in top 24 bits, low 8 bits zeroed.
 */
struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))

static inline int vxlan_hdr_len(const struct tnl_mutable_config *mutable,
				const struct ovs_key_ipv4_tunnel *tun_key)
{
	return VXLAN_HLEN;
}

static struct socket *vxlan_rcv_socket;
static int vxlan_n_tunnels;

static inline struct vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

static __be16 get_src_port(const struct sk_buff *skb,
			   const struct tnl_mutable_config *mutable)
{
	if (mutable->flags & TNL_F_IPSEC)
		return htons(VXLAN_IPSEC_SRC_PORT);

	/* Convert hash into a port between 32768 and 65535. */
	return (__force __be16)OVS_CB(skb)->flow->hash | htons(32768);
}

static struct sk_buff *vxlan_build_header(const struct vport *vport,
					  const struct tnl_mutable_config *mutable,
					  struct dst_entry *dst,
					  struct sk_buff *skb,
					  int tunnel_hlen)
{
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);
	const struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
	__be64 out_key;

	if (tun_key->ipv4_dst)
		out_key = tun_key->tun_id;
	else
		out_key = mutable->out_key;

	udph->dest = htons(VXLAN_DST_PORT);
	udph->source = get_src_port(skb, mutable);
	udph->check = 0;
	udph->len = htons(skb->len - skb_transport_offset(skb));

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(be64_to_cpu(out_key) << 8);

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
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct vxlanhdr *vxh;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;
	struct ovs_key_ipv4_tunnel tun_key;
	int tunnel_type;
	__be64 key;
	u32 tunnel_flags = 0;

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	vxh = vxlan_hdr(skb);
	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff)))
		goto error;

	__skb_pull(skb, VXLAN_HLEN);
	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);

	key = cpu_to_be64(ntohl(vxh->vx_vni) >> 8);

	tunnel_type = TNL_T_PROTO_VXLAN;

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(dev_net(skb->dev), iph->daddr, iph->saddr,
		key, tunnel_type, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	if (mutable->key.daddr && (mutable->flags & TNL_F_IN_KEY_MATCH))
		tunnel_flags = OVS_FLOW_TNL_F_KEY;
	else if (!mutable->key.daddr)
		tunnel_flags = OVS_FLOW_TNL_F_KEY;

	/* Save outer tunnel values */
	tnl_tun_key_init(&tun_key, iph, key, tunnel_flags);
	OVS_CB(skb)->tun_key = &tun_key;

	ovs_tnl_rcv(vport, skb);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

static const struct tnl_ops ovs_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
};

static const struct tnl_ops ovs_ipsec_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
};

/* Random value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_VXLAN 10
static int vxlan_init(void)
{
	int err;
	struct sockaddr_in sin;

	if (vxlan_n_tunnels++)
		return 0;

	err = sock_create(AF_INET, SOCK_DGRAM, 0, &vxlan_rcv_socket);
	if (err)
		goto error;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(VXLAN_DST_PORT);

	err = kernel_bind(vxlan_rcv_socket, (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(vxlan_rcv_socket->sk)->encap_type = UDP_ENCAP_VXLAN;
	udp_sk(vxlan_rcv_socket->sk)->encap_rcv = vxlan_rcv;

	udp_encap_enable();

	return 0;

error_sock:
	sock_release(vxlan_rcv_socket);
error:
	pr_warn("cannot register vxlan protocol handler\n");
	vxlan_n_tunnels--;
	return err;
}

static void vxlan_uninit(void)
{
	if (!--vxlan_n_tunnels)
		sock_release(vxlan_rcv_socket);
}

static struct vport *vxlan_create(const struct vport_parms *parms)
{
	return ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_vxlan_tnl_ops);
}

static void vxlan_exit(void)
{
	vxlan_uninit();
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.flags		= VPORT_F_TUN_ID,
	.init		= vxlan_init,
	.exit		= vxlan_exit,
	.create		= vxlan_create,
	.destroy	= ovs_tnl_destroy,
	.set_addr	= ovs_tnl_set_addr,
	.get_name	= ovs_tnl_get_name,
	.get_addr	= ovs_tnl_get_addr,
	.get_options	= ovs_tnl_get_options,
	.set_options	= ovs_tnl_set_options,
	.get_dev_flags	= ovs_vport_gen_get_dev_flags,
	.is_running	= ovs_vport_gen_is_running,
	.get_operstate	= ovs_vport_gen_get_operstate,
	.send		= ovs_tnl_send,
};
#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
