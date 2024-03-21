# Prevent outside machines from accessing the router machine, except ping.
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -P OUTPUT DROP
iptables -P INPUT DROP

# 1. Outside hosts cannot ping internal hosts.
# 2. Outside hosts can ping the router.
# 3. Internal hosts can ping outside hosts.
# 4. All other packets between the internal and external networks should be blocked.
iptables -A FORWARD -p icmp --icmp-type echo-request -i eth1 -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-reply -i eth0 -j ACCEPT
iptables -P FORWARD DROP

# 1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can only access the telnet
# server on 192.168.60.5, not the other internal hosts.
# 2. Outside hosts cannot access other internal servers.
# 3. Internal hosts can access all the internal servers.
# 4. Internal hosts cannot access external servers.
# 5. In this task, the connection tracking mechanism is not allowed. It will be used in a later task.
iptables -A FORWARD -i eth0 -p tcp --dport 23 -d 192.168.60.5  -j ACCEPT
iptables -A FORWARD -i eth1 -p tcp --sport 23 -s 192.168.60.5 -j ACCEPT
iptables -P FORWARD DROP