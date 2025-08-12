package send

import (
	"bytes"
    "math/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
    "errors"
	"os"
	"os/signal"
    "sync"
    "strconv"
    "strings"
	"syscall"
	"time"
	"io/ioutil"
    "encoding/csv"
    "os/exec"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/cihub/seelog"
    _ "github.com/mattn/go-sqlite3"
    "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
    "github.com/vishvananda/netlink"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"
	"database/sql"
    "http/g"
)

type PingLog struct {
	LossPk   int
	MinDelay float64
	AvgDelay float64
	MaxDelay float64
    UdpDelay float64
    TcpDelay float64
    IcmpDelay float64
}

// const configFile = "../conf/g.Cfg.json"

const pingPort = 65532
const timeout = 2
const payloadLength = 64
const READTIMEOUT = 1 * time.Second
const RETRYTIMES = 30
const SAVECSV = true
const SILENT = true

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/inet.h>

typedef struct {
	u64 ts_ns;
} tcp_start_info_t;

typedef struct {
	u64 daddr;
	u64 delta_us;
} Rtt_t;

typedef struct {
    u32 Tag;
    u64 sk_ptr;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
} debug_event_t;

typedef struct {
    char comm[16];
} proc_name_t;

BPF_HASH(tcp_start_infos, struct sock *, tcp_start_info_t);
BPF_HASH(proc_comm_map, u32, proc_name_t);
BPF_PERF_OUTPUT(ping_events);
BPF_PERF_OUTPUT(debug_events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *skp)
{
    debug_event_t evt = {};
    evt.Tag = 999999;
    evt.sk_ptr = (u64)skp;

    u32 zero = 0;
    proc_name_t *target_comm = proc_comm_map.lookup(&zero);
    if (!target_comm) {
        debug_events.perf_submit(ctx, &evt, sizeof(evt));
        return 0;
    }

    evt.Tag = 777777;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    int match = 1;
    #pragma unroll
    for (int i = 0; i < 9; i++) {
        if (comm[i] != target_comm->comm[i]) {
            match = 0;
            break;
        }
    }
    // for (int i = 0; i < TASK_COMM_LEN; i++) {
    //     evt.comm[i] = comm[i];
    //     evt.target[i] = target_comm->comm[i];
    // }
    if (!match) {
        debug_events.perf_submit(ctx, &evt, sizeof(evt));
        return 0;
    }
    
    evt.saddr = skp->__sk_common.skc_rcv_saddr;
    evt.daddr = skp->__sk_common.skc_daddr;
    evt.sport = skp->__sk_common.skc_num;
    evt.dport = skp->__sk_common.skc_dport;

    evt.Tag = 888888;
    debug_events.perf_submit(ctx, &evt, sizeof(evt));

	tcp_start_info_t info;
	info.ts_ns = bpf_ktime_get_ns();
	tcp_start_infos.update(&skp, &info);

	return 0;
};

int kprobe__tcp_rcv_state_process(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{

    debug_event_t evt = {};
    evt.Tag = 111111;
    evt.sk_ptr = (u64)sk;

	tcp_start_info_t *info = tcp_start_infos.lookup(&sk);
	if (unlikely(!info)) {
        debug_events.perf_submit(ctx, &evt, sizeof(evt));
		return 0;
    }
    
    evt.Tag = 222222;
    debug_events.perf_submit(ctx, &evt, sizeof(evt));

	u16 family = sk->__sk_common.skc_family;
	u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);

	struct tcphdr *tcp = (struct tcphdr *)(skb->head + skb->transport_header);
	u16 tcpflags = *(u16 *)((u8 *)tcp + 12);
	if (!(tcpflags & TCP_FLAG_RST))
		goto exit;

	if (likely(AF_INET == family && PINGPORT == dport)) {
		u64 daddr = bpf_ntohl(sk->__sk_common.skc_daddr);
		u64 ts = info->ts_ns;
		u64 now = bpf_ktime_get_ns();
		u64 delta_us = (now - ts) / 1000ul;

		Rtt_t Rtt;
		Rtt.daddr = daddr;
		Rtt.delta_us = delta_us;

        evt.saddr = sk->__sk_common.skc_rcv_saddr;
        evt.daddr = sk->__sk_common.skc_daddr;
        evt.sport = sk->__sk_common.skc_num;
        evt.dport = dport;

		ping_events.perf_submit(ctx, &Rtt, sizeof(Rtt));
	}

exit:
	tcp_start_infos.delete(&sk);

	return 0;
}
`

type pingEventType struct {
	Daddr   uint64
	DeltaUs uint64
}

type RttEvents struct {
    Rtt       uint64
    Prot      uint64
    // src_ip    uint32
    // dst_ip    uint32
    // src_port  uint16
    // dst_port  uint16
}

type DebugEvents struct {
    Tag     uint64
}

func loadKporbe(m *bpf.Module, name string) {
	probe, err := m.LoadKprobe("kprobe__" + name)
	if err != nil {
		seelog.Error(os.Stderr, "Failed to load %s: %s\n", name, err)
		os.Exit(1)
	}

	if err = m.AttachKprobe(name, probe, -1); err != nil {
		seelog.Error(os.Stderr, "Failed to attach %s: %s\n", name, err)
		os.Exit(1)
	}
}

func setDSCP(fd int, dscp int) error {
    dscpValue := dscp << 2 
    return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, int(dscpValue))
}

// 从 JSON 文件加载配置
func loadConfig(file string) (*g.PingTaskConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, seelog.Errorf("failed to read config file: %s", err)
	}

	var config g.PingTaskConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, seelog.Errorf("failed to parse config file: %s", err)
	}
	return &config, nil
}

var Ip2interface map[string]string
var Ip2LocalIP map[string]net.IP
var Ip2SrcMac map[string]*net.Interface
var Ip2DstMac map[string]net.HardwareAddr

func Init() {
    Ip2interface = make(map[string]string)
    Ip2LocalIP = make(map[string]net.IP)
    Ip2SrcMac = make(map[string]*net.Interface)
    Ip2DstMac = make(map[string]net.HardwareAddr)
    // 遍历所有目标主机和 DSCP 设置
    seelog.Info("destinations: ", g.Cfg.Destinations)
    var dests []string
    if g.Cfg.UseIPv6 {
        dests = g.Cfg.Destinations6
    } else {
        dests = g.Cfg.Destinations
    }
    for _, destination := range dests {
        var destIP net.IP
        if g.Cfg.UseIPv6 {
            destIP = net.ParseIP(destination).To16()
        } else {
            destIP = net.ParseIP(destination)
        }

        _, ifaceName, dstMAC, err := ResolveNextHopMAC(destIP, g.Cfg.UseIPv6)
        // ifaceName, localIP, err := findOutboundInterface(destination, g.Cfg.UseIPv6)
        if err != nil {
            fmt.Println("Failed to find outbound interface: ", err)
        }
        var interIP []netlink.Addr
        if g.Cfg.UseIPv6 {
            interIP, err = netlink.AddrList(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}, netlink.FAMILY_V6)
        } else {
            interIP, err = netlink.AddrList(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}, netlink.FAMILY_V4)
        }
        if err != nil || len(interIP) == 0 {
            seelog.Error("Failed to get local IP for interface: ", ifaceName, " error: ", err)
            continue
        }
        localIP := interIP[0].IP
        fmt.Println("Using interface: ", ifaceName, " with local IP: ", localIP)

        Ip2interface[destination] = ifaceName
        Ip2LocalIP[destination] = localIP
        Ip2DstMac[destination] = dstMAC
        // 获取本地MAC
        iface, err := net.InterfaceByName(ifaceName)
        if err != nil {
            seelog.Error("Cannot find interface: %v", err)
        }
        // seelog.Info("Using interface: ", iface.Name, " with local MAC: ", iface.HardwareAddr, " dstMAC: ", dstMAC)
        Ip2SrcMac[destination] = iface
    }
}

// 支持 IPv4 和 IPv6
func ResolveNextHopMAC(dstIP net.IP, useIPv6 bool) (nextHop net.IP, iface string, mac net.HardwareAddr, err error) {
    num := 0
    for num < RETRYTIMES {
        if useIPv6 {
            _ = exec.Command("ping6", "-c", "1", "-I", iface, nextHop.String()).Run()
        } else {
            _ = exec.Command("ping", "-c", "1", "-I", iface, nextHop.String()).Run()
        }
        time.Sleep(2 * time.Second)
        num = num + 1
        // Step 1: 查路由表
        family := netlink.FAMILY_V4
        if useIPv6 {
            family = netlink.FAMILY_V6
        }
        fmt.Println("dstIP: ", dstIP)
        routes, err := netlink.RouteGet(dstIP)
        if err != nil || len(routes) == 0 {
            fmt.Printf("failed to get route: %v", err)
            if num >= RETRYTIMES {
                return nil, "", nil, fmt.Errorf("failed to get route: %v", err)
            }
            continue
        }
        i := 0
        for i < len(routes) {
            fmt.Printf("routes %d : ", i)
            fmt.Println("Gateway: ", routes[i].Gw)
            i = i + 1
        }
        route := routes[0]

        // Step 2: 解析下一跳 IP（可能是 nil）
        if route.Gw == nil {
            nextHop = dstIP // 说明目标是本地直连，直接发给对方
        } else {
            nextHop = route.Gw
        }

        if (!useIPv6) {
            if nextHop.To4() != nil && nextHop.To4()[3] == 1 {
                fmt.Println("Next hop ends with .1, skipping this route")
                if num >= RETRYTIMES {
                return nil, "", nil, fmt.Errorf("Next hop ends with .1, skipping this route")
                }
                continue
            }
        } else {
            if nextHop.To16() != nil && nextHop.To16()[15] == 1 {
                fmt.Println("Next hop ends with .1, skipping this route")
                if num >= RETRYTIMES {
                return nil, "", nil, fmt.Errorf("Next hop ends with .1, skipping this route")
                }
                continue
            }
        }

        link, err := netlink.LinkByIndex(route.LinkIndex)
        if err != nil {
            fmt.Printf("get link failed: %v", err)
            if num >= RETRYTIMES {
            return nil, "", nil, fmt.Errorf("get link failed: %v", err)
            }
            continue
        }
        iface = link.Attrs().Name

        // Step 3: 查询邻居表
        neighs, err := netlink.NeighList(route.LinkIndex, family)
        if err != nil {
            fmt.Printf("Destination is %s: get neigh failed: %v. the route may be default, but it can't be arrived.", dstIP, err)
            if num >= RETRYTIMES {
                return nil, "", nil, fmt.Errorf("Destination is %s: get neigh failed: %v. the route may be default, but it can't be arrived.", dstIP, err)
            }
            continue
        }
        for _, n := range neighs {
            fmt.Println("dstIP: ", dstIP, "nextip: ", n.IP, " MAC: ", n.HardwareAddr)
            fmt.Println("n.State: ", n.State)
            if n.State & netlink.NUD_REACHABLE != 0 {
                fmt.Println("ready")
                if n.IP.Equal(nextHop) && n.HardwareAddr != nil {
                    fmt.Println("")
                    return nextHop, iface, n.HardwareAddr, nil
                }
            }
        }
    }
    return nextHop, iface, nil, fmt.Errorf("no neighbor entry for %s", nextHop)
}

// func ResolveNextHopMAC(dstIP net.IP, useIPv6 bool) (nextHop net.IP, iface string, mac net.HardwareAddr, err error) {
//     num := 0
//     for num < RETRYTIMES {
//         num = num + 1
//         // Step 1: 查路由表
//         family := netlink.FAMILY_V4
//         if useIPv6 {
//             family = netlink.FAMILY_V6
//         }
//         routes, err := netlink.RouteGet(dstIP)
//         if err != nil || len(routes) == 0 {
//             fmt.Printf("failed to get route: %v", err)
//             if num >= RETRYTIMES {
//                 return nil, "", nil, fmt.Errorf("failed to get route: %v", err)
//             }
//             continue
//         }
//         i := 0
//         for i < len(routes) {
//             fmt.Printf("routes %d : ", i)
//             fmt.Println("Gateway: ", routes[i].Gw)
//             i = i + 1
//         }
//         route := routes[0]

//         // Step 2: 解析下一跳 IP（可能是 nil）
//         if route.Gw == nil {
//             nextHop = dstIP // 说明目标是本地直连，直接发给对方
//         } else {
//             nextHop = route.Gw
//         }

//         link, err := netlink.LinkByIndex(route.LinkIndex)
//         if err != nil {
//             fmt.Printf("get link failed: %v", err)
//             if num >= RETRYTIMES {
//                 return nil, "", nil, fmt.Errorf("get link failed: %v", err)
//             }
//             continue
//         }
//         iface = link.Attrs().Name

//         // Step 3: 查询邻居表
//         neighs, err := netlink.NeighList(route.LinkIndex, family)
//         if err != nil {
//             fmt.Printf("Destination is %s: get neigh failed: %v. the route may be default, but it can't be arrived.", dstIP, err)
//             if num >= RETRYTIMES {
//                 return nil, "", nil, fmt.Errorf("Destination is %s: get neigh failed: %v. the route may be default, but it can't be arrived.", dstIP, err)
//             }
//             continue
//         }
//         for _, n := range neighs {
//             if n.IP.Equal(nextHop) && n.HardwareAddr != nil {
//                 return nextHop, iface, n.HardwareAddr, nil
//             }
//         }
//         time.Sleep(2 * time.Second)
//     }
//     return nextHop, iface, nil, fmt.Errorf("no neighbor entry for %s", nextHop)
// }

// func readRtt_events(Rtt_events *ebpf.Map) {
//     // 创建 perf 事件读取器
//     rd, err := perf.NewReader(Rtt_events, os.Getpagesize())
//     if err != nil {
//         fmt.Printf("Failed to create perf reader: %v", err)
//     }
//     defer rd.Close()

//     // 捕获退出信号
//     sig := make(chan os.Signal, 1)
//     signal.Notify(sig, os.Interrupt)

//     fmt.Println("Listening for RTT events...")

//     for {
//         select {
//         case <-sig:
//             fmt.Println("Exiting...")
//             return
//         default:
//             // 读取事件
//             record, err := rd.Read()
//             if err != nil {
//                 fmt.Printf("Failed to read from perf reader: %v", err)
//                 continue
//             }

//             // 解析事件
//             var event RttEvent
//             if err := binary.Read(record.RawSample, binary.LittleEndian, &event); err != nil {
//                 fmt.Printf("Failed to decode event: %v", err)
//                 continue
//             }

//             // // 打印事件信息
//             // srcIP := net.IPv4(byte(event.SrcIP>>24), byte(event.SrcIP>>16), byte(event.SrcIP>>8), byte(event.SrcIP))
//             // dstIP := net.IPv4(byte(event.DstIP>>24), byte(event.DstIP>>16), byte(event.DstIP>>8), byte(event.DstIP))
//             // fmt.Printf("RTT: %d ns, Src: %s:%d, Dst: %s:%d\n",
//             //     event.RTT, srcIP, event.SrcPort, dstIP, event.DstPort)
//         }
//     }
// }

type SRHOptions struct {
    tcp bool
    udp bool
}

func buildSRH(segments []net.IP, opts SRHOptions) []byte {
	n := len(segments)
	segLeft := byte(n - 1)
	lastEntry := byte(n - 1)

	// SRH fixed header is 8 bytes
	srh := make([]byte, 8+16*n)

    if opts.tcp {
	    srh[0] = byte(layers.IPProtocolTCP)          // Next Header
    } else if opts.udp {
        srh[0] = byte(layers.IPProtocolUDP)          // Next Header
    } else {
        srh[0] = byte(layers.IPProtocolICMPv6)       // Next Header
    }
	srh[1] = 1               // Hdr Ext Len: (16*n / 8) = n*2
	srh[2] = 4               // Type: Routing Type 4
    srh[3] = segLeft         // Segments Left
	srh[4] = lastEntry       // Last Entry
	srh[5] = 0               // Flags
	srh[6] = 0               // Tag (2 bytes)
	srh[7] = 0

	// Segment list (in reverse order)
	for i := 0; i < n; i++ {
		ip := segments[n-1-i].To16()
		copy(srh[8+i*16:8+(i+1)*16], ip)
	}

	// update Hdr Ext Len field: (total len - 8) / 8
	srh[1] = byte((len(srh) - 8) / 8)
	return srh
}

var xdp_file = g.GetRoot() + "/receiver/" + strconv.Itoa(g.Point_index+1) + "response.o"
var use_bpf = true

func runPing(destination string, destination6 string, dscp int, count int, connections int, useIPv6 bool, silent bool) PingLog {
    var mu sync.Mutex
	cond := sync.NewCond(&mu)
	done := connections + 1 // +1 for the perf reader goroutine

    var timeList [3]float64

    // 捕获退出信号
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    if (use_bpf) {
        spec, err := ebpf.LoadCollectionSpec(xdp_file)
        if err != nil {
            fmt.Printf("loading objsection spec: %v", err)
        }
    
        Objs := struct {
            RttEvents *ebpf.Map     `ebpf:"rtt_events"`
            DebugEvents *ebpf.Map `ebpf:"debug_events"`
        }{}
    
        // if spec.Maps["rtt_events"] != nil {
        //     spec.Maps["rtt_events"].PinPath = "/sys/fs/bpf/xdp/globals/rtt_events"
        // }
        // if spec.Maps["debug_events"] != nil {
        //     spec.Maps["debug_events"].PinPath = "/sys/fs/bpf/xdp/globals/debug_events"
        // }

        if err := spec.LoadAndAssign(&Objs, &ebpf.CollectionOptions{
            Maps: ebpf.MapOptions{
                PinPath: "/sys/fs/bpf/xdp/globals",
            },
        }); err != nil {
            fmt.Printf("loading objects: %v", err)
        }
        // defer Objs.RttEvents.Close()
        // defer Objs.DebugEvents.Close()
    
        // 创建 perf 事件读取器
        fmt.Println("size: ", os.Getpagesize())
        fmt.Println("rtt_events: ", Objs.RttEvents)
        fmt.Println("debug_events: ", Objs.DebugEvents)
        rd, err := perf.NewReader(Objs.RttEvents, os.Getpagesize())
        if err != nil {
            fmt.Printf("Failed to create perf reader: %v", err)
        }
        bugrd, err := perf.NewReader(Objs.DebugEvents, os.Getpagesize())
        if err != nil {
            fmt.Printf("Failed to create perf reader: %v", err)
        }
        defer rd.Close()
        defer bugrd.Close()
    
        go func() {
            startTime := time.Now()
            timeout := 2 * time.Second
            for {
                fmt.Println("Reading perf time: ", time.Since(startTime), " timeout: ", timeout)
                if time.Since(startTime) > timeout {
                    break
                }
                select {
                case <-sig:
                    fmt.Println("Exiting...")
                    return
                default:
                    if !silent {
                        fmt.Println("Reading perf events...")
                    }
                    // 读取事件
                    rd.SetDeadline(time.Now().Add(READTIMEOUT))
                    record, err := rd.Read()
                    if errors.Is(err, os.ErrDeadlineExceeded) {
                        continue
                    }
                    if err != nil {
                        fmt.Printf("Failed to read from perf reader: %v", err)
                        return
                    }
    
                    // 解析事件
                    reader := bytes.NewReader(record.RawSample)
                    var event RttEvents
                    if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
                        fmt.Printf("Failed to decode event: %v", err)
                        continue
                    }
    
                    deltaUs := float64(event.Rtt) / 1e3
                    // timeList = append(timeList, deltaUs)
                    // seelog.Info("tcp RST from ", destination, ": time=", deltaUs, " us\n")
                    // if !silent {
                    if deltaUs < 1e6 {
                        if event.Prot == 0 {
                            timeList[0] = deltaUs
                            fmt.Println("tcp RST from ", destination, ": time=", deltaUs, " us\n")
                        } else if event.Prot == 1 {
                            timeList[1] = deltaUs
                            fmt.Println("udp RST from ", destination, ": time=", deltaUs, " us\n")
                        }
                    }
                }
            }
            cond.L.Lock()
            done--
            if done == 0 {
                cond.Broadcast()
            }
            cond.L.Unlock()
        }()
    }
    
    dest := destination
    if useIPv6 {
        dest = destination6
    }
    for i := 0; i < connections; i++ {
        // if !silent {
        //     seelog.Infof("Starting connection %d\n", i)
        // }
        go func() {
            // TCP
            ifaceName := Ip2interface[dest]
            localIP := Ip2LocalIP[dest]
            if ifaceName == "" || localIP == nil {
                seelog.Error("Interface not found for destination or localIP: ", dest, " ", ifaceName, " ", localIP)
            }
            handle, err := pcap.OpenLive(ifaceName, 65535, false, pcap.BlockForever)
            if err != nil {
                seelog.Error(err)
            }
            defer handle.Close()

            srcMAC := Ip2SrcMac[dest].HardwareAddr
            dstMAC := Ip2DstMac[dest]
            
            srcPort := layers.TCPPort(pingPort)
            dstPort := layers.TCPPort(pingPort)
            srcPortudp := layers.UDPPort(pingPort)
            dstPortudp := layers.UDPPort(pingPort)

            // === 构造各层 ===
            eth := &layers.Ethernet{
                SrcMAC: srcMAC,
                DstMAC: dstMAC,
            }
            if useIPv6 {
                eth.EthernetType = layers.EthernetTypeIPv6
            } else {
                eth.EthernetType = layers.EthernetTypeIPv4
            }

            ip := &layers.IPv4{
                Version:  4,
                TTL:      64,
                Protocol: layers.IPProtocolTCP,
                SrcIP:    localIP.To4(),
                DstIP:    net.ParseIP(destination).To4(),
            }
            fmt.Println("localIP: ", localIP.To4(), " destination: ", destination)

            ipv6 := &layers.IPv6{
                Version:  6,
                HopLimit: 64,
                SrcIP:    net.ParseIP(g.Cfg.Addr6).To16(),
                DstIP:    net.ParseIP("fc00:1:6::2").To16(),
                NextHeader: layers.IPProtocolIPv6Routing,
            }

            segmentList := []net.IP{
                net.ParseIP("fc00:1:4::2"),
                net.ParseIP("fc00:1:5::2"),
                net.ParseIP("fc00:1:6::2"),
            }
            // Note: segment list is stored in *reverse order* in SRH
            rawSRHtcp := buildSRH(segmentList, SRHOptions{tcp: true, udp: false})
            rawSRHudp := buildSRH(segmentList, SRHOptions{tcp: false, udp: true})

            tcp := &layers.TCP{
                SrcPort: srcPort,
                DstPort: dstPort,
                SYN:     true,
                Seq:     rand.Uint32() % 2,
                // Seq:     65432,
                Window:  14600,
            }

            udp := &layers.UDP{
                SrcPort: srcPortudp,
                DstPort: dstPortudp,
                Length:  uint16(payloadLength),
                Checksum: 0,
            }

            icmp := &layers.ICMPv6{
                TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
                Checksum: 0,
            }
            
            // Set DSCP value
            dscpValue := byte(dscp << 2)
            ip.TOS = dscpValue
            ipv6.TrafficClass = dscpValue

            if useIPv6 {
                err = tcp.SetNetworkLayerForChecksum(ipv6)
            } else {
                err = tcp.SetNetworkLayerForChecksum(ip)
            }
            if err != nil {
                seelog.Error(err)
            }

            if useIPv6 {
                err = udp.SetNetworkLayerForChecksum(ipv6)
            } else {
                err = udp.SetNetworkLayerForChecksum(ip)
            }
            if err != nil {
                seelog.Error(err)
            }

            if useIPv6 {
                err = icmp.SetNetworkLayerForChecksum(ipv6)
            } else {
                err = icmp.SetNetworkLayerForChecksum(ip)
            }
            if err != nil {
                seelog.Error(err)
            }

            // Create a dictionary with direction, ecmp tag, and send time
            // data := map[string]interface{}{
            //     "direction": "outbound",
            //     "ecmp_tag":  "1010101010",
            //     "send_time": int64(0),
            // }

            // // Append the JSON string to the payload
            // payload := []byte(data)

            var direct uint64
            // var ecmpTag string
            var sendTime uint64
            var src uint32
            var dst uint32
            // var src_ip net.IP
            // var segments []net.IP
            direct = 0
            // ecmpTag = "1000000000"
            sendTime = 0
            src = uint32(g.Point_index)
            val, _ := strconv.ParseUint(strings.Split(destination, ".")[2], 10, 32)
            dst = uint32(val)
            // src_ip = localIP.To16()
            // segments = []net.IP{
            //     net.ParseIP("fc00:1:6::2"),
            //     net.ParseIP("fc00:1:5::2"),
            //     net.ParseIP("fc00:1:4::2"),
            // }
            payload := make([]byte, payloadLength)
            binary.BigEndian.PutUint64(payload[0:8], sendTime)
            // copy(payload[8:18], ecmpTag)
            // binary.BigEndian.PutUint64(payload[8:18], ecmpTag)
            binary.BigEndian.PutUint64(payload[8:16], direct)
            binary.BigEndian.PutUint32(payload[16:20], src)
            binary.BigEndian.PutUint32(payload[20:24], dst)

            // copy(payload[26:42], src_ip.To16())
            // for i, segment := range segments {
            //     copy(payload[42+i*16:58+i*16], segment.To16())
            // }
            for i := 24; i < payloadLength; i++ {
                payload[i] = byte(i % 256)
            }
            
            buffertcp := gopacket.NewSerializeBuffer()
            opts := gopacket.SerializeOptions{
                ComputeChecksums: true,
                FixLengths:       true,
            }
            
            if useIPv6 {
                err = gopacket.SerializeLayers(buffertcp, opts, eth, ipv6, gopacket.Payload(rawSRHtcp), tcp, gopacket.Payload(payload))
            } else {
                err = gopacket.SerializeLayers(buffertcp, opts, eth, ip, tcp, gopacket.Payload(payload))
            }
            if err != nil {
                fmt.Println("Packet error: (tcp) ", err)
            }
            outgoingPackettcp := buffertcp.Bytes()
            if err := handle.WritePacketData(outgoingPackettcp); err != nil {
                seelog.Error(err)
            }

            bufferudp := gopacket.NewSerializeBuffer()
            opts = gopacket.SerializeOptions{
                ComputeChecksums: true,
                FixLengths:       true,
            }

            if useIPv6 {
                err = gopacket.SerializeLayers(bufferudp, opts, eth, ipv6, gopacket.Payload(rawSRHudp), udp, gopacket.Payload(payload))
            } else {
                ip.Protocol = layers.IPProtocolUDP
                udp.SetNetworkLayerForChecksum(ip)
                err = gopacket.SerializeLayers(bufferudp, opts, eth, ip, udp, gopacket.Payload(payload))
            }
            if err != nil {
                fmt.Println("Packet error: (udp) ", err)
            }
            outgoingPacketudp := bufferudp.Bytes()
            if err := handle.WritePacketData(outgoingPacketudp); err != nil {
                seelog.Error(err)
            }
            
            var cmd *exec.Cmd
            var output []byte
            if useIPv6 {
                cmd = exec.Command("ping", "-c", "1", dest)
                output, err = cmd.Output()
                if err != nil {
                    seelog.Error("Failed to execute ping command: ", err)
                    return
                }
            } else {
                cmd = exec.Command("ping", "-c", "1", dest)
                output, err = cmd.Output()
                if err != nil {
                    seelog.Error("Failed to execute ping command: ", err)
                    return
                }
            }

            lines := bytes.Split(output, []byte("\n"))
            for _, line := range lines {
                if bytes.Contains(line, []byte("time=")) {
                    parts := bytes.Fields(line)
                    for _, part := range parts {
                        if bytes.HasPrefix(part, []byte("time=")) {
                            timeStr := string(part[5:]) // Extract the RTT value
                            rtt, err := strconv.ParseFloat(timeStr, 64)
                            if err != nil {
                                seelog.Error("Failed to parse RTT: ", err)
                            } else {
                                rtt = rtt * 1000 // Convert to us
                                // timeList = append(timeList, rtt)
                                timeList[2] = rtt
                                fmt.Println("ICMP RTT from ", dest, ": time=", rtt, " us")
                            }
                            break
                        }
                    }
                }
            }

            // seelog.Infof("Sent SYN with %d bytes payload and DSCP value %d", len(payload), dscp)
            time.Sleep(timeout * time.Second)
            cond.L.Lock()
            done--
            if done == 0 {
                cond.Broadcast()
            }
            cond.L.Unlock()
        }()
    }

    fmt.Println("Times00")
    cond.L.Lock()
    for done > 0 {
        cond.Wait()
    }
    cond.L.Unlock()
    fmt.Println("Times0")
    
    stat := PingLog{
        LossPk: 0,
        MinDelay: 0,
        AvgDelay: 0,
        MaxDelay: 0,
        TcpDelay: 0,
        UdpDelay: 0,
        IcmpDelay: 0,
    }

    if use_bpf {
        times := len(timeList)

        var sumTimeUs float64
        var maxTimeUs float64
        var minTimeUs float64
        var dropCount int
        maxTimeUs = 0
        minTimeUs = 9999999999
        sumTimeUs = 0
        // fmt.Println("Times1")
        for _, timeUs := range timeList {
            if timeUs == 0 {
                dropCount++
            } else {
                sumTimeUs += timeUs
                if timeUs > maxTimeUs {
                    maxTimeUs = timeUs
                }
                if timeUs < minTimeUs {
                    minTimeUs = timeUs
                }
            }
        }
        if dropCount > 0 {
            fmt.Println("dropCount: ", dropCount, " tcpdelay: ", timeList[0], " udpdelay: ", timeList[1])
        }
        if times == 0 {
            seelog.Warn("No events captured, possible reasons: BPF not triggered, no TCP responses, or PID mismatch")
            return PingLog{
                LossPk:   count * connections, // 所有都失败了
                MinDelay: 0,
                AvgDelay: 0,
                MaxDelay: 0,
                TcpDelay: 0,
                UdpDelay: 0,
                IcmpDelay: 0,
            }
        }
        avgTime := sumTimeUs / float64(times)
        // seelog.Info("\n\ntcp RST from ", dest, ": average time=", avgTime, " us\n")
        stat = PingLog{
            LossPk: dropCount,
            MinDelay: minTimeUs,
            AvgDelay: avgTime,
            MaxDelay: maxTimeUs,
            TcpDelay: timeList[0],
            UdpDelay: timeList[1],
            IcmpDelay: timeList[2],
        }
    }


    return stat
}

var sendtime = 0

func Send() {
    // config, err := loadConfig(configFile)
    // if err != nil {
    //     seelog.Error(os.Stderr, "Failed to load config: %s\n", err)
    //     os.Exit(1)
    // }

    // // 定期执行
    // ticker := time.NewTicker(time.Duration(g.Cfg.Epoch) * time.Second) // 每 `g.Cfg.Epoch` 秒执行一次
    // defer ticker.Stop() // 在退出时停止 ticker

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, os.Kill)

    done := make(chan struct{})

    go func() {
        // seelog.Info("New round of ping\n")
        results := make(map[string]map[int]PingLog)

        // 遍历所有目标主机和 DSCP 设置
        for di, destination6 := range g.Cfg.Destinations6 {
            results[destination6] = make(map[int]PingLog)
            results[g.Cfg.Destinations[di]] = make(map[int]PingLog)
            for _, dscp := range g.Cfg.Dscp {
                stat := runPing(g.Cfg.Destinations[di], destination6, dscp, 
                    g.Cfg.PingConfig.Count, g.Cfg.PingConfig.Connections, g.Cfg.UseIPv6, SILENT)
                if g.Cfg.UseIPv6 {
                    results[destination6][dscp] = stat
                } else {
                    results[g.Cfg.Destinations[di]][dscp] = stat
                }
            }
        }

        if SAVECSV {
            // 打开或创建文件
            // 如果文件存在，则继续写入
            // 如果文件不存在，则创建新文件
            file, err := os.OpenFile(g.GetRoot() + "/csv/pingLog-" + strconv.Itoa(g.Point_index) + ".csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
            if err != nil {
                fmt.Println("无法打开文件", err)
            }
            defer file.Close()
            // 如果文件是新创建的，则写入表头
            fi, err := file.Stat()
            if err != nil {
                fmt.Println("无法获取文件信息", err)
            }
            // 创建 CSV writer
            writer := csv.NewWriter(file)
            defer writer.Flush() // 刷新缓冲区
            if fi.Size() == 0 {
                // 写入表头
                header := []string{"Source", "Destination", "DSCP", "MaxDelay", "MinDelay", "AvgDelay", "LossPk", "TcpDelay", "UdpDelay", "IcmpDelay"}
                err := writer.Write(header)
                if err != nil {
                    fmt.Println("写入 CSV 文件时出错:", err)
                }
            } 
            // 如果文件存在，则继续写入结果
            if g.Cfg.UseIPv6 {
                for res := range results {
                    for dscp := range results[res] {
                        row := []string{
                            g.Cfg.Addr6,
                            res,
                            strconv.Itoa(dscp),
                            strconv.FormatFloat(results[res][dscp].MaxDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].MinDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].AvgDelay, 'f', 3, 64),
                            strconv.Itoa(results[res][dscp].LossPk),
                            strconv.FormatFloat(results[res][dscp].TcpDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].UdpDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].IcmpDelay, 'f', 3, 64),
                        }
                        err := writer.Write(row)
                        if err != nil {
                            fmt.Println("写入 CSV 文件时出错:", err)
                        }
                    }
                }
            } else {
                for res := range results {
                    for dscp := range results[res] {
                        row := []string{
                            g.Cfg.Addr,
                            res,
                            strconv.Itoa(dscp),
                            strconv.FormatFloat(results[res][dscp].MaxDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].MinDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].AvgDelay, 'f', 3, 64),
                            strconv.Itoa(results[res][dscp].LossPk),
                            strconv.FormatFloat(results[res][dscp].TcpDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].UdpDelay, 'f', 3, 64),
                            strconv.FormatFloat(results[res][dscp].IcmpDelay, 'f', 3, 64),
                        }
                        err := writer.Write(row)
                        if err != nil {
                            fmt.Println("写入 CSV 文件时出错:", err)
                        }
                    }
                }
            }
        }
        
        fmt.Println("Ping results length:", len(results))
        
        // 存储每个结果
        for res := range results {
            for dscp := range results[res] {
                seelog.Info("PingStorage: ", results[res][dscp], " ", res, " ", dscp)
                PingStorage(results[res][dscp], res, dscp)
            }
        }
        sendtime = sendtime + 1
        fmt.Println("发送次数: ", sendtime)
        close(done)
    }()

    <-done
    return
}

func PingStorage(pingres PingLog , Addr string, dscp int) {
	logtime := time.Now().Format("2006-01-02 15:04:05")
	// seelog.Info("[func:StartPing] ", "(", logtime, ")Starting PingStorage ", Addr)
	db, err_open := sql.Open("sqlite3", g.GetRoot() + "/database/pingLog-" + strconv.Itoa(g.Point_index) + ".db")
    if err_open != nil {
        seelog.Error("[func:StartPing] Failed to open database: ", err_open)
        return
    }
    
    // if there is no database, create it
    createTableSQL := `
        CREATE TABLE IF NOT EXISTS pingLog (
        logtime  VARCHAR (16),
        dscp     INT  ,
        target   VARCHAR (39),
        maxdelay FLOAT,
        mindelay FLOAT,
        avgdelay FLOAT,
        losspk   INT,
        TcpDelay FLOAT,
        UdpDelay FLOAT,
        IcmpDelay FLOAT
    );`
    // execute the create table sql
    _, err_create := db.Exec(createTableSQL)
    if err_create != nil {
        seelog.Error("[func:StartPing] Failed to create table: ", err_create)
        return
    }

    // storage: (logtime, target, dscp, maxdelay, mindelay, avgdelay, losspk, TcpDelay, UdpDelay, IcmpDelay)
    command := "INSERT INTO [pingLog] (logtime, target, dscp, maxdelay, mindelay, avgdelay, losspk, TcpDelay, UdpDelay, IcmpDelay) values('" + logtime + "','" + Addr + "','" + strconv.Itoa(dscp) + "','" + strconv.FormatFloat(pingres.MaxDelay, 'f', 3, 64) + "','" + strconv.FormatFloat(pingres.MinDelay, 'f', 3, 64) + "','" + strconv.FormatFloat(pingres.AvgDelay, 'f', 3, 64) + "','" + strconv.Itoa(pingres.LossPk) + "','" + strconv.FormatFloat(pingres.TcpDelay, 'f', 3, 64) + "','" + strconv.FormatFloat(pingres.UdpDelay, 'f', 3, 64) + "','" + strconv.FormatFloat(pingres.IcmpDelay, 'f', 3, 64) + "')"
	_, err_insert := db.Exec(command)
	if err_insert != nil {
		seelog.Error("[func:StartPing] ", "(", logtime, ")PingStorage Error:", err_insert)
	}
	// seelog.Info("[func:StartPing] ", "(", logtime, ")PingStorage Success")
	defer db.Close()
}

// 把 uint32 的 IP 地址转换为字符串表示（IPv4）
func intToIP(n uint32) string {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, n)
    return ip.String()
}

func PingClean() {
    // 清理 pingLog 数据库
    db, err_open := sql.Open("sqlite3", g.GetRoot() + "/database/pingLog-" + strconv.Itoa(g.Point_index) + ".db")
    if err_open != nil {
        seelog.Error("[func:PingClean] Failed to open database: ", err_open)
        return
    }
    
    // 删除 pingLog 表
    _, err_delete := db.Exec("DROP TABLE IF EXISTS pingLog")
    if err_delete != nil {
        seelog.Error("[func:PingClean] Failed to delete table: ", err_delete)
        return
    }
    
    defer db.Close()
}