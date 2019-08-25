
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/string.h>

static struct nf_hook_ops *nfho = NULL;
#define GNTAG "[GN-CYF]: " 

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct ethhdr *mh = eth_hdr(skb);
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
    // protocol : IPPROTO_UDP,IPPROTO_TCP
    /// udph = udp_hdr(skb);
    //ntohs(udph->dest)

    int src_port ;
	int dest_port;
	char src_ip[64];
	char dest_ip[64];
 
	printk(KERN_INFO GNTAG "id: %d, protocol: %d, ttl: %d",iph->id, iph->protocol,iph->ttl);

	// get port
	if (iph->protocol == IPPROTO_UDP)
	{	
		udph = udp_hdr(skb);
		dest_port = 	ntohs(udph->dest);
		src_port = 	ntohs(udph->source);

	}else if (iph->protocol == IPPROTO_TCP){
		tcph = tcp_hdr(skb);
		dest_port = 	ntohs(tcph->dest);
		src_port = 	ntohs(tcph->source);
	}
	// get ip
	snprintf(src_ip, 16, "%pI4", &iph->saddr); 
	snprintf(dest_ip, 16, "%pI4", &iph->daddr); 
	

	printk(KERN_INFO GNTAG "\n\
	src_vlan_id: %s\n\
	src_ip: %s\n\
	src_port: %d\n\
	dest_ip: %s\n\
	dest_port: %d\n", 
	skb->vlan_tci,
	src_ip,
	src_port,
	dest_ip,
	dest_port);

	printk(KERN_INFO GNTAG "src_mac = %x:%x:%x:%x:%x:%x\n",mh->h_source[0],mh->h_source[1],mh->h_source[2],mh->h_source[3],mh->h_source[4],mh->h_source[5]);  
	printk(KERN_INFO GNTAG "dest_mac = %x:%x:%x:%x:%x:%x\n",mh->h_dest[0],mh->h_dest[1],mh->h_dest[2],mh->h_dest[3],mh->h_dest[4],mh->h_dest[5]);  

	//demo5 chan IP 13.229.188.59 
	if (strcmp("13.229.188.59",src_ip) == 0)
		return NF_DROP;
	else
	return NF_ACCEPT;


}

static int __init  gn_cyf_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho->hook 	= (nf_hookfn*)hfunc;		
	nfho->hooknum 	= NF_INET_PRE_ROUTING;	
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;	
	
    printk(KERN_INFO GNTAG " registered");

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
