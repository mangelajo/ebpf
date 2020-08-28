#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include "bpf_macros.h"	


#define tc_actok_if_no_room_for(structure) \
	if no_room_for(structure, data_end) { return TC_ACT_OK; }	



__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	tc_actok_if_no_room_for(eth);

	if (bpf_htons(eth->h_proto) != ETH_P_IP) {
		return TC_ACT_OK;
	}

	struct iphdr *ip = (struct iphdr*)(data + sizeof(struct ethhdr));

	tc_actok_if_no_room_for(ip);

	char ipd[48];

	src_dest_printer(ipd, ip);
	
	printk("ingress %s\n", ipd);

    return TC_ACT_OK;
}

__section("egress")
int tc_egress(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	tc_actok_if_no_room_for(eth);

	if (bpf_htons(eth->h_proto) != ETH_P_IP) {
		return TC_ACT_OK;
	}

	struct iphdr *ip = (struct iphdr*)(data + sizeof(struct ethhdr));

	tc_actok_if_no_room_for(ip);


	char ipd[48];

	src_dest_printer(ipd, ip);
	
	printk("egress  %s\n", ipd);


    return TC_ACT_OK;
}



char __license[] __section("license") = "GPL";
