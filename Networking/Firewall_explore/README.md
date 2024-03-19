# Answer in my observation

# Task 1:

## Task 1B:

- NF_INET_PRE_ROUTING: this hook will be triggered for all incoming traffic after entering the network stack.

- NF_INET_LOCAL_IN: this hook is triggered after an incoming packet, whose destination address is local system, has been routed.

- NF_INET_FORWARD: this hook is triggered after an incoming packet has been routing, and the packet is forwarded to another host, which means it affects to both in WAN and LAN.

- NF_INET_LOCAL_OUT: this hook is triggered by outgoing packets/outbound traffic after entering the network stack.

- NF_INET_POST_ROUTING: this hook is triggered by outgoing packets/outbound traffic after routing determination and before sending out on the wire.