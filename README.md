# findingsd: Log connections matching PF criteria to mysql
This is a simple OpenBSD daemon, based on `spamlogd(8)`, that monitors a
`pflog(4)` interface for packets and inserts their details into a database
table.

This daemon is used by echoCTF to log connections to targets and award points
to users, but it can easily be adapted to perform other tasks.


## Setup
The setup is quite simple
1. Configure a pflog(4) interface
2. Add required PF rules
3. Create the database table to log your packets
4. Compile, install and start the service
5. Profit

### Configure pflog(4)
```
echo "up">/etc/hostname.pflog1
```
### Add PF rules
```
match log (to pflog1) inet proto tcp to <web_servers> port 22
```
### Create database table
```
mysql mydatabase<findingsd.sql
```

### Compile, install and start the service
```
git clone https://github.com/findingsd.git
cd findingsd
make
install -o root -g wheel -m 0555 findingsd /usr/local/sbin/findingsd
install -o root -g wheel -m 0555 findingsd.rc /etc/rc.d/findingsd
rcctl set findingsd status on
rcctl set findingsd flags -l pflog1 -n DATABASE -u USER
```

### Test the service
Run by hand and send a packet to based on your PF rules.

```
findingsd -D -l pflog1 -n DATABASE_NAME -u DATABASE_USER
```

The daemon will start printing out packets similar to the following
```
[Tue Jan  7 14:11:43 2020] SRC: 10.10.0.10 => DST: => 10.0.100.34:22, PROTO: tcp
```

Check the database table to confirm that the packets gets logged successfully.
