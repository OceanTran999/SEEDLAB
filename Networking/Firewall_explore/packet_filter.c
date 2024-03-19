// Refs:
// [1]: https://tldp.org/LDP/lkmpg/2.4/lkmpg.pdf
// [2]: https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html
// [3]: https://stackoverflow.com/questions/467557/what-is-meant-by-the-term-hook-in-programming: Meaning of term "hook" in Linux Kernel programming
// [4]: https://www.sobyte.net/post/2022-04/understanding-netfilter-and-iptables/
// [5]: https://stackoverflow.com/questions/9296835/convert-source-ip-address-from-struct-iphdr-to-string-equivalent-using-linux-ne: print IP from "struct iphdr*"
// [6]: https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>

static struct nf_hook_ops hook1, hook2;

// sk_buff: socket buffer which is converted from the received packet after being
//             added to the processing queue
unsigned int printInfo(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
   struct iphdr* ip;
   char* hook;
   char* proto;

   // Print out information of hook
   switch (state->hook){
      case NF_INET_PRE_ROUTING:
         hook = "PRE_ROUTING";
         break;
      
      case NF_INET_POST_ROUTING:
         hook = "POST_ROUTING";
         break;

      case NF_INET_LOCAL_IN:
         hook = "LOCAL_IN";
         break;
      
      case NF_INET_LOCAL_OUT:
         hook = "LOCAL_OUT";
         break;
      
      case NF_INET_FORWARD:
         hook = "FORWARD";
         break;
      
      default:
         hook = "Unknown type of hook";
         break;
   }

   printk(KERN_INFO "Hook: %s\n", hook);

   // Print out type of protocol
   ip = ip_hdr(skb);
   switch(ip->protocol){
      case IPPROTO_UDP:
         proto = "UDP"; break;
      
      case IPPROTO_TCP:
         proto = "TCP"; break;
      
      case IPPROTO_ICMP:
         proto = "ICMP"; break;
      
      default:
         proto = "Other";
   }

   printk(KERN_INFO "Protocol is: %s\n", proto);

   // Print out IP Source and IP Destination
   printk(KERN_INFO "IP Source: %pI4 --- IP Destination: %pI4\n", &(ip->saddr), &(ip->daddr));

   return NF_ACCEPT;
}

unsigned int blockUDP(void* priv, struct sk_buff* buff, const struct nf_hook_state* state)
{
   struct iphdr* ip;
   struct udphdr* udp;

   char target_ip[16] = "8.8.8.8";
   unsigned short int port = 53;
   unsigned int ip_addr;

   if(!buff)
      return NF_ACCEPT;
   
   ip = ip_hdr(buff);

   // Convert IP Address from dotted decimal to 32-bit binary
   in4_pton(target_ip, -1, (unsigned char*)&ip_addr, '\0', NULL);

   // Block UDP Connection to 8.8.8.8 port 53
   if(ip->protocol == IPPROTO_UDP)
   {
      udp = udp_hdr(buff);
      if(ip->daddr == ip_addr && ntohs(udp->dest) == port)
      {
         printk(KERN_WARNING "Dropping packet to %pI4 -- UDP protocol -- port %d\n", &(ip->daddr), port);
         return NF_DROP;
      }
   }

   return NF_ACCEPT;
}

static int register_filter(void)
{
   printk(KERN_INFO "Registering filters.\n");

   // Hook 1
   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_IN;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   // Hook 2
   hook2.hook = blockUDP;
   hook2.hooknum = NF_INET_POST_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

static void remove_filter(void)
{
   printk(KERN_INFO "Removing filters.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(register_filter);
module_exit(remove_filter);

MODULE_LICENSE("GPL");