cd /app/agent/receiver
# rm -rf /app/receiver/*.ll
# rm -rf /app/receiver/*.o
make clean
make
sleep 0.5

echo SELF=$(echo $1 | awk -F '-' '{print $2}')

for iface in $(ls /sys/class/net); do
    # make NIC=$iface uninstall
    # echo $1 | awk -F '-' '{print $2}'
    make NIC=$iface SELF=$(echo $1 | awk -F '-' '{print $2}') install
done

cd /app/sh
# bash log.sh $1 & bash $1.sh
bash $1.sh