
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
    // protocol : IPPROTO_UDP,IPPROTO_TCP
    /// udph = udp_hdr(skb);
    //ntohs(udph->dest)

	 
	
	return NF_DROP;
}

static int __init  gn_cyf_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_PRE_ROUTING;	
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;	
	
    printk(KERN_INFO "GN: cyf registered");

	nf_register_net_hook(&init_net, nfho);
}

static void __exit gn_cyf_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(gn_cyf_init);
module_exit(gn_cyf_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Giay Nhap");
MODULE_DESCRIPTION("CYF Driver");
