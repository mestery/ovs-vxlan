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
#include <linux/xfrm.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"
#include "vport-vxlan.h"

static struct socket *vxlan_rcv_socket;
static int vxlan_n_tunnels;

static __be16 get_src_port(const struct sk_buff *skb,
                           const struct tnl_mutable_config *mutable)
{
        if (mutable->flags & TNL_F_IPSEC)
                return htons(VXLAN_IPSEC_SRC_PORT);

        /* Convert hash into a port between 32768 and 65535. */
        return (__force __be16)OVS_CB(skb)->flow->hash | htons(32768);
}

static void vxlan_build_header(const struct vport *vport,
			       const struct tnl_mutable_config *mutable,
			       void *header)
{
	struct udphdr *udph = header;
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);

	udph->dest = htons(VXLAN_DST_PORT);
	udph->check = 0;

	vxh->vx_flags = htonl(VXLAN_FLAGS);
	vxh->vx_vni = htonl(be64_to_cpu(mutable->out_key) << 8);
}

static struct sk_buff *vxlan_update_header(const struct vport *vport,
					   const struct tnl_mutable_config *mutable,
					   struct dst_entry *dst,
					   struct sk_buff *skb)
{
	struct udphdr *udph = udp_hdr(skb);
	struct vxlanhdr *vxh = (struct vxlanhdr *)(udph + 1);

	if (mutable->flags & TNL_F_OUT_KEY_ACTION)
		vxh->vx_vni = htonl(be64_to_cpu(OVS_CB(skb)->tun_id) << 8);

	udph->source = get_src_port(skb, mutable);
	udph->len = htons(skb->len - skb_transport_offset(skb));

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

static bool sec_path_esp(struct sk_buff *skb)
{
	struct sec_path *sp = skb_sec_path(skb);

	if (sp) {
		int i;

		for (i = 0; i < sp->len; i++)
			if (sp->xvec[i]->id.proto == XFRM_PROTO_ESP)
				return true;
	}

	return false;
}

/* Called with rcu_read_lock and BH disabled. */
static int vxlan_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	struct vxlanhdr *vxh;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;
	int tunnel_type;
	__be64 key;

	if (unlikely(!pskb_may_pull(skb, VXLAN_HLEN + ETH_HLEN)))
		goto error;

	vxh = vxlan_hdr(skb);
	if (unlikely(vxh->vx_flags != htonl(VXLAN_FLAGS) ||
		     vxh->vx_vni & htonl(0xff)))
		goto error;

	__skb_pull(skb, VXLAN_HLEN);

	key = cpu_to_be64(ntohl(vxh->vx_vni) >> 8);

	tunnel_type = TNL_T_PROTO_VXLAN;
	if (sec_path_esp(skb))
		tunnel_type |= TNL_T_IPSEC;

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(dev_net(skb->dev), iph->daddr, iph->saddr,
		key, tunnel_type, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	skb_postpull_rcsum(skb, skb_transport_header(skb), VXLAN_HLEN + ETH_HLEN);

	/* Save outer tunnel values */
	OVS_CB(skb)->tun_ipv4_src = iph->saddr;
	OVS_CB(skb)->tun_ipv4_dst = iph->daddr;
	OVS_CB(skb)->tun_ipv4_tos = iph->tos;
	OVS_CB(skb)->tun_ipv4_ttl = iph->ttl;

	if (mutable->flags & TNL_F_IN_KEY_MATCH)
		OVS_CB(skb)->tun_id = key;
	else
		OVS_CB(skb)->tun_id = 0;

	ovs_tnl_rcv(vport, skb, iph->tos);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

static const struct tnl_ops ovs_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN,
	.ipproto	= IPPROTO_UDP,
	.dport		= htons(VXLAN_DST_PORT),
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
	.update_header	= vxlan_update_header,
};

static const struct tnl_ops ovs_ipsec_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN | TNL_T_IPSEC,
	.ipproto	= IPPROTO_UDP,
	.sport		= htons(VXLAN_IPSEC_SRC_PORT),
	.dport		= htons(VXLAN_DST_PORT),
	.hdr_len	= vxlan_hdr_len,
	.build_header	= vxlan_build_header,
	.update_header	= vxlan_update_header,
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
	struct nlattr *flags_nlattr;
	struct vport *vport;
	int error;

	error = vxlan_init();
	if (error)
		return ERR_PTR(error);

	flags_nlattr = nla_find_nested(parms->options, OVS_TUNNEL_ATTR_FLAGS);
	if (!flags_nlattr || nla_len(flags_nlattr) != sizeof(u32))
		return ERR_PTR(-EINVAL);

	if (nla_get_u32(flags_nlattr) & TNL_F_IPSEC)
	    vport = ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_ipsec_vxlan_tnl_ops);
	else
	    vport = ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_vxlan_tnl_ops);

	if (IS_ERR(vport))
		vxlan_uninit();
	return vport;
}

static void vxlan_destroy(struct vport *vport)
{
	vxlan_uninit();
	return ovs_tnl_destroy(vport);
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.flags		= VPORT_F_TUN_ID,
	.create		= vxlan_create,
	.destroy	= vxlan_destroy,
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
