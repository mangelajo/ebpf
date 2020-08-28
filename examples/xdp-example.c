#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "bpf_macros.h"	


#define xdp_pass_if_no_room_for(structure) \
	if no_room_for(structure, data_end) { return XDP_PASS; }	

__section("prog")
int xdp_log_dest(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	xdp_pass_if_no_room_for(eth);

	if (bpf_htons(eth->h_proto) != ETH_P_IP) {
		return XDP_PASS;
	}

	struct iphdr *ip = (struct iphdr*)(data + sizeof(struct ethhdr));

	xdp_pass_if_no_room_for(ip);

	__u32 ip4 = bpf_ntohl(ip->daddr);

	printk("ip dst: %x len: %d\n", ip4, data_end-data);

	return XDP_PASS;
}

char __license[] __section("license") = "GPL";
