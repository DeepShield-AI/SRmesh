service frr start
vtysh -c 'conf t' -c 'ipv6 forwarding'
vtysh -c 'conf t' -c 'router ospf' -c 'redistribute bgp' -c 'redistribute connected' -c 'redistribute local'
vtysh -c 'conf t' -c 'router ospf' -c 'network 192.168.1.0/24 area 0'
cd /app

# point-xxx, xxx is the container index
mv http/http_service http/point-003
./http/point-003 container_name
