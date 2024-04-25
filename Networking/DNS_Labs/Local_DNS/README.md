# Answer in my observationn
## Task 1
- To make the attack successful, I need to clear the DNS cache due to the speed of the real and spoofed packet.
- After cleaning the DNS cache of the local DNS server, we can see the modified information of the DNS response message.

## Task 2
- To spoof the response packets from other DNS server, I use the interface of the router that sends packets out the Internet.

## Task 3
- In the the local user's terminal, when using `dig` command will not display the `AUTHORITY SECTION`. However, when dumping the DNS cache into a file, we can see the attack is successful.

## Task 4
- Adding `google.com` domain to `AUTHORITY SECTION`. However, the cache or the dumped file only display the `example.com` domain with its spoofed nameserver `ns.attacker32.com`.
- When using Wireshark, we can see both the `google.com` and `example.com` domains are still in `AUTHORITY SECTION` of the DNS response packet.

&rarr; In my opinion, the reason why the `google.com` domain is not successfully cached is because the `google.com` domain is not relevant to the domain in query message, which is `example.com`.

## Task 5
- After successfully spoofing the sniffed DNS query packet with the `www.example.com` domain and sending to the local DNS server, we can see that the `example.com` domain in `AUTHORITY SECTION` is cached. However, all nameservers of the `www.example.com` domain in the `ADDITIONAL SECTION` is not cached.
- In case that the domain in query message is `example.com`, after the attack, only the `ns.attacker32.com` nameserver in `ADDITIONAL SECTION` is cached.

&rarr; In my opinion, the reason why the `ns.attacker32.com` in `ADDITIONAL SECTION` is cached is because it depends on the domain in the request/query message. If the query domain in packet is matched with the domain in `AUTHORITY SECTION`, it will display the information of the nameservers in the `AUTHORITY SECTION`, and the details of nameservers in `ADDTIONAL SECTION` are finally saved to the DNS cache. For example, the `ns.attacker32.com` nameserver is in the `example.com` domain, if the query packet contains this domain, it will show the information of `ns.attacker32.com` nameserver (ex: IPv4/IPv6 address) in the `ADDITIONAL SECTION`. The `ns.example.net` and `www.facebook.com` nameservers are not in `AUTHORITY SECTION`, so they are not cached.
