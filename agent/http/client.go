package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"strings"

	"http/g"
	"http/pb"

	"github.com/cihub/seelog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
)

// DEFINE CONFIGURATION CONSTANTS
const (
	THDAVGDELAY  = "200" // Threshold for average delay in milliseconds
	THDCHECKSEC  = "900" // Threshold for check interval in seconds
	THDLOSS      = "30"  // Threshold for packet loss percentage
	THDOCCNUM    = "3"   // Threshold for occurrence number
)

type AgentInfo struct {
	Index int
	Name  string
	IP    string
	IPv6  string
	Slice int
}

var taskClient pb.TaskDistributionClient
var statusClient pb.ProbeStatusClient
var dataClient pb.ProbeDataClient

var Docker = true
var Host = false

func Agentgrpc() {
	// 建立连接
	var conn *grpc.ClientConn
	var err_connect error
	if g.Point_index == 0 || Host {
		conn, err_connect = 
		grpc.Dial(
			"127.0.0.1:50051", 
			grpc.WithInsecure(),
			grpc.WithBlock(),
			grpc.WithConnectParams(grpc.ConnectParams{
				Backoff: backoff.Config{
					BaseDelay:  2 * time.Second,  // 初始重试间隔
					Multiplier: 1.5,              // 每次失败后间隔扩大倍数
					MaxDelay:   10 * time.Second, // 最大重试间隔
					Jitter:     0.2,              // 加入 20% 随机抖动，防止惊群
				},
				MinConnectTimeout: 5 * time.Second, // 每次 Dial 尝试的最大时间
			}),
		)
	} else {
		dialip := "controller:50051"
		if !Docker {
			dialip = g.Cfg.ControllerAddr + ":50051"
		}
		conn, err_connect = 
		grpc.Dial(
			dialip,
			grpc.WithInsecure(),
			grpc.WithBlock(),
			grpc.WithConnectParams(grpc.ConnectParams{
				Backoff: backoff.Config{
					BaseDelay:  2 * time.Second,  // 初始重试间隔
					Multiplier: 1.5,              // 每次失败后间隔扩大倍数
					MaxDelay:   10 * time.Second, // 最大重试间隔
					Jitter:     0.2,              // 加入 20% 随机抖动，防止惊群
				},
				MinConnectTimeout: 5 * time.Second, // 每次 Dial 尝试的最大时间
			}),
		)
	}
	if err_connect != nil {
		seelog.Error("无法连接服务端: %v", err_connect)
	}
	seelog.Info("连接服务端成功")
	defer conn.Close()

	// 创建客户端 stub
	taskClient = pb.NewTaskDistributionClient(conn)
	statusClient = pb.NewProbeStatusClient(conn)
	dataClient = pb.NewProbeDataClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	agentinfo := AgentInfo{
		Index: 0,
		Name:  "乌鲁木齐",
		IP:    "10.0.1.2",
		IPv6:  "fc00:1::2",
		Slice: 0,
	}

	agentinfo.Index = g.Point_index
	agentinfo.Name = g.Cfg.Name
	fmt.Println("g.Name: ", g.Cfg.Name)
	agentinfo.IP = g.Cfg.Addr
	// agentinfo.IPv6 =
	// agentinfo.Slice = g.Cfg.Slice
	str, _ := json.Marshal(agentinfo)
	fmt.Println("agentinfo: ", string(str))

	// 1. 调用 GetProbeDestinations
	taskResp, err_get := taskClient.GetProbeDestinations(ctx, &pb.AgentGetTaskRequest{
		AgentInfo: string(str),
	})
	if err_get != nil {
		seelog.Error("调用 GetProbeDestinations 失败: %v", err_get)
	}
	// fmt.Println("任务请求： ", str)
	fmt.Println("response: ", taskResp)
	// if taskResp != nil {
	// 	fmt.Println("okk")
	// }
	// seelog.Info("任务下发结果:", taskResp.Task)
	fmt.Println("任务下发结果:", taskResp.Task)

	var tasks []string
	if err_unmarshal := json.Unmarshal([]byte(taskResp.Task), &tasks); err_unmarshal != nil {
		seelog.Error("解析任务失败: %v", err_unmarshal)
	}

	g.Cfg.Destinations = make([]string, len(tasks))
	g.Cfg.Destinations6 = make([]string, len(tasks))
	for i, task := range tasks {
		if len(strings.Split(task, " ")) < 2 {
			g.Cfg.Destinations[i] = task
			continue
		}
		if i >= len(g.Cfg.Destinations) {
			g.Cfg.Destinations = append(g.Cfg.Destinations, strings.Split(task, " ")[0])
		} else {
			g.Cfg.Destinations[i] = strings.Split(task, " ")[0]
		}
		if i >= len(g.Cfg.Destinations6) {
			g.Cfg.Destinations6 = append(g.Cfg.Destinations6, strings.Split(task, " ")[1])
		} else {
			g.Cfg.Destinations6[i] = strings.Split(task, " ")[1]
		}
	}
	// TODO: Ping ipv6
	// g.SelfCfg.Ping = tasks
	// {
    //                 "Addr": "10.1.3.2",
    //                 "Addr6": "fc00:0001:3::2",
    //                 "Name": "北大",
    //                 "Thdavgdelay": "200",
    //                 "Thdchecksec": "900",
    //                 "Thdloss": "30",
    //                 "Thdoccnum": "3"
    //             },
	g.SelfCfg.Ping = make([]map[string]string, len(tasks))
	for i, task := range tasks {
		parts := strings.Split(task, " ")
		if len(parts) < 2 {
			g.SelfCfg.Ping[i] = map[string]string{
				"Addr": task,
				"Addr6": "",
				"Name": g.Cfg.Name,
				"Thdavgdelay": THDAVGDELAY,
				"Thdchecksec": THDCHECKSEC,
				"Thdloss": THDLOSS,
				"Thdoccnum": THDOCCNUM,
			}
			continue
		}
		g.SelfCfg.Ping[i] = map[string]string{
			"Addr": parts[0],
			"Addr6": parts[1],
			"Name": g.Cfg.Name,
			"Thdavgdelay": THDAVGDELAY,
			"Thdchecksec": THDCHECKSEC,
			"Thdloss": THDLOSS,
			"Thdoccnum": THDOCCNUM,
		}
	}
	selfConfig := g.Cfg.Network[g.Cfg.Addr]
	selfConfig.Ping = g.SelfCfg.Ping
	g.Cfg.Network[g.Cfg.Addr] = selfConfig
	// fmt.Println("Cfg: ", g.Cfg)
	g.SaveConfig()

	// 2. 调用 ReportProbeStatus
	statusResp, err_report := statusClient.ReportProbeStatus(ctx, &pb.AgentUploadReportRequest{
		Report: "status: good",
	})
	if err_report != nil {
		seelog.Error("调用 ReportProbeStatus 失败: %v", err_report)
	}
	// if statusResp != nil {
	// 	fmt.Println("okk")
	// }
	fmt.Println("状态上报结果:", statusResp)

	// 3. 调用 ReportProbeData
	dataResp, err_data := dataClient.ReportProbeData(ctx, &pb.AgentUploadDataRequest{
		Data: "{\"latency\": 10}",
	})
	if err_data != nil {
		seelog.Error("调用 ReportProbeData 失败: %v", err_data)
	}
	// if dataResp != nil {
	// 	fmt.Println("okk")
	// }
	fmt.Println("数据上报结果:", dataResp)
}

// func TaskDistribution() {
// 	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
// 	// defer cancel()

// 	// agentinfo := AgentInfo{
// 	// 	Index: 0,
// 	// 	Name:  "乌鲁木齐",
// 	// 	IP:    "10.0.1.2",
// 	// 	IPv6:  "fc00:1::2",
// 	// 	Slice: 0,
// 	// }

// 	// agentinfo.Index = g.Point_index
// 	// agentinfo.Name = g.Cfg.Name
// 	// agentinfo.IP = g.Cfg.Addr
// 	// // agentinfo.IPv6 =
// 	// // agentinfo.Slice = g.Cfg.Slice
// 	// str, _ := json.Marshal(agentinfo)
// 	// fmt.Println("agentinfo: ", agentinfo)
// 	// fmt.Println("agentinfo: ", string(str))
// 	// seelog.Debug("agentinfo: ", agentinfo)
// 	// seelog.Debug("agentinfo: ", string(str))

// 	// // 1. 调用 GetProbeDestinations
// 	// taskResp, err := taskClient.GetProbeDestinations(ctx, &pb.AgentGetTaskRequest{
// 	// 	AgentInfo: string(str),
// 	// })
// 	// if err != nil {
// 	// 	seelog.Error("调用 GetProbeDestinations 失败: %v", err)
// 	// }
// 	// seelog.Info("任务请求： ", str)
// 	// // seelog.Info("任务下发结果:", taskResp.Task)
// 	// // fmt.Println("任务下发结果:", taskResp.Task)

// 	// var tasks []string
// 	// if err := json.Unmarshal([]byte(taskResp.Task), &tasks); err != nil {
// 	// 	seelog.Error("解析任务失败: %v", err)
// 	// }

// 	// g.Cfg.Destinations = tasks
// 	// g.SelfCfg.Ping = tasks
// 	// selfConfig := g.Cfg.Network[g.Cfg.Addr]
// 	// selfConfig.Ping = tasks
// 	// g.Cfg.Network[g.Cfg.Addr] = selfConfig
// 	// g.SaveConfig()
// }
