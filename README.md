# findingsd
Daemon tracking services discovered by players

This is a copy of spamlogd, re-purposed for echoCTF with a few modifications to make it log into MySQL.

pf.conf
```
table <tcp_10.0.100.14_22> persist
match log (to pflog1) inet proto tcp from !<tcp_10.0.100.14_22> to 10.0.100.14 port 22 tagged OFFENSE_REGISTERED
```
