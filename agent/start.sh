cd /app/agent/receiver
# rm -rf /app/receiver/*.ll
# rm -rf /app/receiver/*.o
make clean
make

for iface in $(ls /sys/class/net | grep '^eth'); do
    # make NIC=$iface uninstall
    make NIC=$iface install
done

cd /app/sh
bash $1.sh
