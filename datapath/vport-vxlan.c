 /*
 * Copyright (c) 2011 Nicira, Inc.
 * Copyright (c) 2012 Cisco Systems, Inc.
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
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

/* Default to the OTV port, per the VXLAN IETF draft. */
#define VXLAN_DST_PORT 8472

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

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @port: The UDP port number.
 * @socket: The socket created for this port number.
 * @count: How many ports are using this socket/port.
 * @hash_node: Hash node.
 */
struct vxlan_port {
	u16 port;
	struct socket *vxlan_rcv_socket;
	int count;

	/* Protected by RTNL lock. */
	struct hlist_node hash_node;
};

/* Protected by RTNL lock. */
static struct hlist_head *vxlan_ports;
#define VXLAN_SOCK_HASH_BUCKETS 64

/**
 * struct vxlan_if - Maps port names to UDP port numbers
 * @port: The UDP port number this interface is using.
 * @ifname: The name of the interface.
 * @hash_node: Hash node.
 */
struct vxlan_if {
	u16 port;
	char ifname[IFNAMSIZ];

	/* Protected by RTNL lock. */
	struct hlist_node hash_node;
};

/* Protected by RTNL lock. */
static struct hlist_head *vxlan_ifs;
#define VXLAN_IF_HASH_BUCKETS 64

static struct hlist_head *vxlan_hash_bucket(struct net *net, u16 port)
{
	unsigned int hash = jhash(&port, sizeof(port), (unsigned long) net);
	return &vxlan_ports[hash & (VXLAN_SOCK_HASH_BUCKETS - 1)];
}

static struct vxlan_port *vxlan_port_exists(struct net *net, u16 port)
{
	struct hlist_head *bucket = vxlan_hash_bucket(net, port);
	struct vxlan_port *vxlan_port;
	struct hlist_node *node;

	hlist_for_each_entry(vxlan_port, node, bucket, hash_node) {
		if (vxlan_port->port == port)
			return vxlan_port;
	}

	return NULL;
}

static struct hlist_head *vxlanif_hash_bucket(struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &vxlan_ifs[hash & (VXLAN_IF_HASH_BUCKETS - 1)];
}

static struct vxlan_if *vxlan_if_by_name(struct net *net, const char *name)
{
	struct hlist_head *bucket = vxlanif_hash_bucket(net, name);
	struct vxlan_if *vxlan_if;
	struct hlist_node *node;

	hlist_for_each_entry(vxlan_if, node, bucket, hash_node) {
		if (!strcmp(vxlan_if->ifname, name))
			return vxlan_if;
	}

	return NULL;
}

static inline struct vxlanhdr *vxlan_hdr(const struct sk_buff *skb)
{
	return (struct vxlanhdr *)(udp_hdr(skb) + 1);
}

/* The below used as the min/max for the UDP port range */
#define VXLAN_SRC_PORT_MIN      32768
#define VXLAN_SRC_PORT_MAX      61000

/* Compute source port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct sk_buff *skb)
{
	unsigned int range = (VXLAN_SRC_PORT_MAX - VXLAN_SRC_PORT_MIN) + 1;
	u32 hash = OVS_CB(skb)->flow->hash;

	return (__force u16)(((u64) hash * range) >> 32) + VXLAN_SRC_PORT_MIN;
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

	if (mutable->dst_port)
		udph->dest = htons(mutable->dst_port);
	else
		udph->dest = htons(VXLAN_DST_PORT);
	udph->source = htons(get_src_port(skb));
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

	if (mutable->flags & TNL_F_IN_KEY_MATCH || !mutable->key.daddr)
		tunnel_flags = OVS_TNL_F_KEY;
	else
		key = 0;

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

/* Random value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_VXLAN 10
static int vxlan_socket_init(struct vxlan_port *vxlan_port)
{
	int err;
	struct sockaddr_in sin;

	err = sock_create(AF_INET, SOCK_DGRAM, 0, &vxlan_port->vxlan_rcv_socket);
	if (err)
		goto error;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(vxlan_port->port);

	err = kernel_bind(vxlan_port->vxlan_rcv_socket, (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(vxlan_port->vxlan_rcv_socket->sk)->encap_type = UDP_ENCAP_VXLAN;
	udp_sk(vxlan_port->vxlan_rcv_socket->sk)->encap_rcv = vxlan_rcv;

	udp_encap_enable();

	return 0;

error_sock:
	sock_release(vxlan_port->vxlan_rcv_socket);
error:
	pr_warn("cannot register vxlan protocol handler\n");
	return err;
}

static const struct nla_policy vxlan_policy[OVS_TUNNEL_ATTR_MAX + 1] = {
	[OVS_TUNNEL_ATTR_DST_PORT] = { .type = NLA_U16 },
};

static int vxlan_tunnel_setup(struct net *net, const char *linkname,
			     struct nlattr *options)
{
	struct nlattr *a[OVS_TUNNEL_ATTR_MAX + 1];
	int err;
	u16 dst_port;
	struct vxlan_port *vxlan_port;
	struct vxlan_if *vxlan_if;

	if (!options) {
		err = -EINVAL;
		goto out;
	}

	err = nla_parse_nested(a, OVS_TUNNEL_ATTR_MAX, options, vxlan_policy);
	if (err)
		goto out;

	if (a[OVS_TUNNEL_ATTR_DST_PORT])
		dst_port = nla_get_u16(a[OVS_TUNNEL_ATTR_DST_PORT]);
	else
		dst_port = VXLAN_DST_PORT;

	/* Verify if we already have a socket created for this port */
	vxlan_port = vxlan_port_exists(net, dst_port);
	if (vxlan_port) {
		vxlan_port->count++;
		err = 0;
		goto out;
	}

	/* Add a new socket for this port */
	vxlan_port = kmalloc(sizeof(struct vxlan_port), GFP_KERNEL);
	if (!vxlan_port) {
		err = -ENOMEM;
		goto out;
	}
	memset (vxlan_port, 0, sizeof(struct vxlan_port));

	vxlan_port->port = dst_port;
	vxlan_port->count++;
	hlist_add_head(&vxlan_port->hash_node,
		       vxlan_hash_bucket(net, dst_port));

	err = vxlan_socket_init(vxlan_port);
	if (err)
		goto error_vxlan_if;

	vxlan_if = kmalloc(sizeof(struct vxlan_if), GFP_KERNEL);
	if (!vxlan_if) {
		err = -ENOMEM;
		goto error_vxlan_if;
	}
	memset(vxlan_if, 0, sizeof(*vxlan_if));

	vxlan_if->port = dst_port;
	memcpy(vxlan_if->ifname, linkname, IFNAMSIZ);
	hlist_add_head(&vxlan_if->hash_node,
		       vxlanif_hash_bucket(net, linkname));

out:
	return err;
error_vxlan_if:
	hlist_del(&vxlan_port->hash_node);
	kfree(vxlan_port);
	goto out;
}

static int vxlan_set_options(struct vport *vport, struct nlattr *options)
{
	int err;
	const char *vname = vport->ops->get_name(vport);

	err = vxlan_tunnel_setup(ovs_dp_get_net(vport->dp), vname, options);
	if (err)
		goto out;

	err = ovs_tnl_set_options(vport, options);

out:
	return err;
}

static const struct tnl_ops ovs_vxlan_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_VXLAN,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= vxlan_hdr_len,
	.pre_tunnel	= NULL,
	.build_header	= vxlan_build_header,
};

void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_if *vxlan_if;
	struct vxlan_port *vxlan_port;
	const char *vname = vport->ops->get_name(vport);

	vxlan_if = vxlan_if_by_name(ovs_dp_get_net(vport->dp), vname);
	if (!vxlan_if)
		goto out;

	vxlan_port = vxlan_port_exists(ovs_dp_get_net(vport->dp),
					 vxlan_if->port);
	if (!vxlan_port)
		goto out_if;

	if (!--vxlan_port->count) {
		sock_release(vxlan_port->vxlan_rcv_socket);
		hlist_del(&vxlan_port->hash_node);
		kfree(vxlan_port);
	}

out_if:
	hlist_del(&vxlan_if->hash_node);
	kfree(vxlan_if);
out:
	ovs_tnl_destroy(vport);
}

static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	int err;

	err = vxlan_tunnel_setup(ovs_dp_get_net(parms->dp), parms->name,
						parms->options);
	return ovs_tnl_create(parms, &ovs_vxlan_vport_ops, &ovs_vxlan_tnl_ops);
}

static int vxlan_init(void)
{
	int err;

	vxlan_ifs = kzalloc(VXLAN_IF_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!vxlan_ifs) {
		err = -ENOMEM;
		goto out;
	}

	vxlan_ports = kzalloc(VXLAN_SOCK_HASH_BUCKETS * sizeof(struct hlist_head),
				GFP_KERNEL);
	if (!vxlan_ports) {
		err = -ENOMEM;
		goto free_ifs;
	}

out:
	return 0;
free_ifs:
	kfree(vxlan_ifs);
	goto out;
}

static void vxlan_exit(void)
{
	kfree(vxlan_ports);
	kfree(vxlan_ifs);
}

const struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.flags		= VPORT_F_TUN_ID,
	.init		= vxlan_init,
	.exit		= vxlan_exit,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.set_addr	= ovs_tnl_set_addr,
	.get_name	= ovs_tnl_get_name,
	.get_addr	= ovs_tnl_get_addr,
	.get_options	= ovs_tnl_get_options,
	.set_options	= vxlan_set_options,
	.get_dev_flags	= ovs_vport_gen_get_dev_flags,
	.is_running	= ovs_vport_gen_is_running,
	.get_operstate	= ovs_vport_gen_get_operstate,
	.send		= ovs_tnl_send,
};
#else
#warning VXLAN tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
