// Preventing other computers to telnet into the VM

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

struct nf_hook_ops hook;

unsigned int blockTelnet(void* priv, struct sk_buff* packet, const struct nf_hook_state* state)
{
    char* protocol;
    char* hook;
    unsigned int port = 23;

    // Print out type of hook
    switch(state->hook)
    {
        case NF_INET_PRE_ROUTING:
            hook = "PRE_ROUTING";   break;
        
        case NF_INET_LOCAL_IN:
            hook = "LOCAL_IN";   break;
        
        case NF_INET_FORWARD:
            hook = "FORWARD";   break;
        
        case NF_INET_LOCAL_OUT:
            hook = "LOCAL_OUT";   break;
        
        case NF_INET_POST_ROUTING:
            hook = "POST_ROUTING";   break;
        
        default:
            hook = "Unknown hook...";   break;
    }
    printk(KERN_INFO "Type of hook: %s\n", hook);

    // Protocol Information
    struct iphdr* ip = ip_hdr(packet);
    struct tcphdr* tcp;

    switch(ip->protocol)
    {
        case IPPROTO_TCP:
            protocol = "TCP";   break;
        
        case IPPROTO_UDP:
            protocol = "UDP";   break;
        
        case IPPROTO_ICMP:
            protocol = "ICMP";   break;
        
        default:
            protocol = "Other...";  break;
    }
    printk(KERN_INFO "Protocol: %s\n", protocol);

    // Block Telnet connection
    printk(KERN_INFO "IP Source: %pI4 -- IP Destination: %pI4\n", &(ip->saddr), &(ip->daddr));  // print info traffic
    if(ip->protocol == IPPROTO_TCP)
    {
        tcp = tcp_hdr(packet);
        printk(KERN_INFO "Destination Port: %d\n", ntohs(tcp->dest));
        if(ntohs(tcp->dest) == port)
        {
            printk(KERN_WARNING "Dropping packet that connect to Telnet Server.\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static int hook_register(void)
{
    printk(KERN_INFO "Register a hook.\n");

    // Create a hook
    hook.hook = blockTelnet;
    hook.hooknum = NF_INET_FORWARD;
    hook.pf = PF_INET;
    hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook);

    return 0;
}

static void hook_delete(void)
{
    printk(KERN_INFO "Closing a hook.\n");
    nf_unregister_net_hook(&init_net, &hook);
}

module_init(hook_register);
module_exit(hook_delete);

MODULE_LICENSE("GPL");