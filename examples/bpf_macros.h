
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

#define no_room_for(varst, data_end) ((void *)varst + sizeof(*varst) > (void *)data_end)



// silliest algorithm for printing a byte in ebpf, in direct order
char __inline *dec_str(char *dst, __u8 byte) {
	int trg = 0;
	unsigned int prev = byte/100;
	if (prev) {
		*dst++ = (char)prev+'0';
		trg = 1;
	}
	prev = (byte - prev*100)/10;
	if (trg || prev) {
		*dst++ = (char)prev+'0';
	}
	*dst++ = (char)(byte%10) + '0';
	*dst = '\0';
	return dst;
} 

__inline char *ip_printer(char *ipa, __u32 ip4) {
	char *p;

	p = dec_str(ipa, ip4>>24);
	*p++='.';
	p = dec_str(p, (ip4>>16)&0xff);
	*p++='.';
	p = dec_str(p, (ip4>>8)&0xff);
	*p++='.';
	p = dec_str(p, (ip4)&0xff);
	return p;
}

__inline void src_dest_printer(char *ips, struct iphdr *ip) {

	__u32 ip4_d = bpf_ntohl(ip->daddr);
	__u32 ip4_s = bpf_ntohl(ip->saddr);

	char *p = ip_printer(ips, ip4_s);
	*p++ = ' ';
	*p++ = '-';
	*p++ = '>';
	*p++ = ' ';
	ip_printer(p, ip4_d);
}
