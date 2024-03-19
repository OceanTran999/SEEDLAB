// Preventing other computers to ping the VM

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops hook;

unsigned int blockICMP(void* priv, struct sk_buff* buff, const struct nf_hook_state* state)
{
    struct iphdr* ip = ip_hdr(buff);
    char* proto;
    char* hook_str;

    // Print out Protocol
    switch(ip->protocol)
    {
        case IPPROTO_ICMP:
            proto = "ICMP"; break;

        case IPPROTO_TCP:
            proto = "TCP"; break;

        case IPPROTO_UDP:
            proto = "UDP"; break;
        
        default:
            proto = "Other..."; break;
    }
    printk(KERN_INFO "Protocol: %s\n", proto);

    // Print out type of hook
    switch(state->hook){
        case NF_INET_PRE_ROUTING:
            hook_str = "PRE_ROUTING";   break;
        
        case NF_INET_LOCAL_IN:
            hook_str = "LOCAL_IN";   break;

        case NF_INET_FORWARD:
            hook_str = "FORWARD";   break;
        
        case NF_INET_LOCAL_OUT:
            hook_str = "LOCAL_OUT";   break;
        
        case NF_INET_POST_ROUTING:
            hook_str = "POST_ROUTING";   break;

        default:
            hook_str = "Unknown...";    break;
    }
    printk(KERN_INFO "Type of hook: %s.\n", hook_str);

    // Block ICMP to VM
    printk(KERN_INFO "IP Source: %pI4 -- IP Destination: %pI4.\n", &(ip->saddr), &(ip->daddr)); // print IP Src - Dst

    if(strcmp(proto, "ICMP") == 0)
    {
        printk(KERN_WARNING "Dropping ICMP packet to VM.\n");
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static int hook_register(void)
{
    printk(KERN_INFO "Registering a hook.\n");

    // Create hook
    hook.hook = blockICMP;
    hook.hooknum = NF_INET_FORWARD;
    hook.priority = NF_IP_PRI_FIRST;
    hook.pf = PF_INET;
    nf_register_net_hook(&init_net, &hook);

    return 0;
}

static void delete_hook(void)
{
    printk(KERN_INFO "Deleting hook...\n");
    nf_unregister_net_hook(&init_net, &hook);
}
module_init(hook_register);
module_exit(delete_hook);

MODULE_LICENSE("GPL");