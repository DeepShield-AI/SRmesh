.PHONY: all clean install uninstall

CLANG ?= clang
LLC   ?= llc
TC 	  ?= tc
NIC   ?= eth0
SELF  ?= 1

XDP_OBJ := response.o
XDP_SEC ?= xdp
TC_OBJ = response.o
TC_SEC ?= tc
IN_OBJ := egress.o
IN_SEC ?= in
SUDO ?= 

MAP_DIR := /sys/fs/bpf/shared_maps
MAP_PATH := $(MAP_DIR)/rtt_start

CPU ?= $(shell nproc)
IP4_STR = $(shell ip -4 addr show dev $(NIC) | grep inet | awk '{print $$2}' | cut -d/ -f1)
IP6_STR = $(shell ip -6 addr show dev $(NIC) | grep inet6 | awk 'NR == 1 {print $$2}' | cut -d/ -f1)
IP4 = $(shell echo $(IP4_STR) | awk -F. '{printf "0x%02X%02X%02X%02X\n", $$1, $$2, $$3, $$4}')
IP6 = $(shell echo $(IP6_STR) | awk -F. '{printf "0x%02X%02X%02X%02X\n", $$1, $$2, $$3, $$4}')

# MAC_ARRAY := $(shell echo $(LOCAL_MAC) | sed 's/://g' | sed 's/^/0x/')
XDP_INCLUDES ?= -I./lib -I./ -I./include
XDP_FLAGS ?= -O2 -target bpf -nostdinc -g -DCPU=$(CPU) -DIP4=$(IP4) -DIP6=$(IP6) -DSELF=$(SELF) -DPAYLOAD_LENGTH=64
TC_FLAGS ?= -O2 -target bpf -g
# CLANF_FLAGS += -Wall -Wextra -Wshadow -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end -Wdeclaration-after-statement
# LLC_FLAGS ?= -march=bpf -mcpu=probe -mattr=dwarfris -filetype=obj

all: $(XDP_OBJ)
# all: $(XDP_OBJ) $(RTT_OBJ)

# $(TC_OBJ): %.o: %.c
# 	$(CLANG) $(XDP_INCLUDES) $(XDP_FLAGS) -c $^ -o $@

$(XDP_OBJ): %.o: %.c
	$(CLANG) $(XDP_INCLUDES) $(XDP_FLAGS) -c $^ -o $(SELF)$@

clean:
	-rm -rf *.ll *.o

install: $(XDP_OBJ) $(TC_OBJ)
# $(SUDO) bpftool prog loadall $(XDP_OBJ) /sys/fs/bpf/xdp_$(NIC) type xdp map name rtt_start pinned $(MAP_PATH)
# $(SUDO) ip -force link set dev $(NIC) xdpgeneric obj $(XDP_OBJ) sec $(XDP_SEC) pinned /sys/fs/bpf/xdp_$(NIC)
# $(SUDO) tc qdisc replace dev $(NIC) clsact
# $(SUDO) bpftool prog loadall $(TC_OBJ) /sys/fs/bpf/tc_$(NIC) type sched_cls map name rtt_start pinned $(MAP_PATH)
# $(SUDO) tc filter add dev $(NIC) egress bpf da obj $(TC_OBJ) sec $(TC_SEC)

	$(SUDO) ip -force link set dev $(NIC) xdpgeneric obj $(SELF)$(XDP_OBJ) sec $(XDP_SEC)
	$(SUDO) tc qdisc replace dev $(NIC) clsact
	$(SUDO) tc filter add dev $(NIC) egress bpf da obj $(SELF)$(TC_OBJ) sec $(TC_SEC)

# $(SUDO) tc filter add dev $(NIC) ingress bpf da obj $(IN_OBJ) sec $(IN_SEC)

$(MAP_PATH): $(XDP_OBJ)
	$(SUDO) bpftool prog load $(XDP_OBJ) /sys/fs/bpf/tmp_xdp type xdp
	$(SUDO) cp -a /sys/fs/bpf/tmp_xdp/maps/rtt_start /sys/fs/bpf/shared_maps/
	$(SUDO) rm /sys/fs/bpf/tmp_xdp

uninstall:
	$(SUDO) ip link set dev $(NIC) xdpgeneric off
	$(SUDO) tc qdisc del dev $(NIC) clsact