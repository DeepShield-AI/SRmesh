package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"sync"
	
	"github.com/cihub/seelog"
	"github.com/jakecoffman/cron"
	_ "github.com/mattn/go-sqlite3"
	"github.com/wcharczuk/go-chart"
	"github.com/wcharczuk/go-chart/drawing"

	"http/g"
	"http/send"
	"http/funcs"
)

// send ping data to the http
func handleRequest(w http.ResponseWriter, r *http.Request) {
	// if !AuthUserIp(r.RemoteAddr) && !AuthAgentIp(r.RemoteAddr, true) {
	// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
	// 	http.Error(w, o, 401)
	// 	return
	// }
	r.ParseForm()
	if len(r.Form["ip"]) == 0 {
		o := "Missing Param !"
		http.Error(w, o, 406)
		return
	}
	var tableip string
	var timeStart int64
	var timeEnd int64
	var timeStartStr string
	var timeEndStr string
	var dscp string
	tableip = r.Form["ip"][0]
	// Finish: parse the dscp value
	if len(r.Form["dscpLevel"]) > 0 {
		dscp = r.Form["dscpLevel"][0]
	} else {
		dscp = "0"
	}
	// Parse the start and end times
	if len(r.Form["starttime"]) > 0 && len(r.Form["endtime"]) > 0 {
		timeStartStr = r.Form["starttime"][0]
		if timeStartStr != "" {
			tms, _ := time.Parse("2006-01-02 15:04", timeStartStr)
			timeStart = tms.Unix() - 8*60*60
		} else {
			timeStart = time.Now().Unix() - 2*60*60
			timeStartStr = time.Unix(timeStart, 0).Format("2006-01-02 15:04")
		}
		timeEndStr = r.Form["endtime"][0]
		if timeEndStr != "" {
			tmn, _ := time.Parse("2006-01-02 15:04", timeEndStr)
			timeEnd = tmn.Unix() - 8*60*60
		} else {
			timeEnd = time.Now().Unix()
			timeEndStr = time.Unix(timeEnd, 0).Format("2006-01-02 15:04")
		}
	} else {
		timeStart = time.Now().Unix() - 2*60*60
		timeStartStr = time.Unix(timeStart, 0).Format("2006-01-02 15:04")
		timeEnd = time.Now().Unix()
		timeEndStr = time.Unix(timeEnd, 0).Format("2006-01-02 15:04")
	}
	cnt := int((timeEnd - timeStart) / 60)
	var lastcheck []string
	var maxdelay []string
	var mindelay []string
	var avgdelay []string
	var losspk []string
	var tcpdelay []string
	var udpdelay []string
	var icmpdelay []string
	timwwnum := map[string]int{}
	// 网络性能序列初始化
	for i := 0; i < cnt+1; i++ {
		ntime := time.Unix(timeStart, 0).Format("2006-01-02 15:04")
		timwwnum[ntime] = i
		lastcheck = append(lastcheck, ntime)
		maxdelay = append(maxdelay, "0")
		mindelay = append(mindelay, "0")
		avgdelay = append(avgdelay, "0")
		losspk = append(losspk, "0")
		tcpdelay = append(tcpdelay, "0")
		udpdelay = append(udpdelay, "0")
		icmpdelay = append(icmpdelay, "0")
		timeStart = timeStart + 60
	}

	// Connect to the SQLite database
	db, err := sql.Open("sqlite3", g.GetRoot() + "/database/pingLog-" + strconv.Itoa(g.Point_index) + ".db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	seelog.Info("[func:/api/ping.json] dscp: ", dscp)
	querySql := "SELECT logtime, maxdelay, mindelay, avgdelay, losspk, TcpDelay, UdpDelay, IcmpDelay FROM `pingLog` where target='" + tableip + "' and dscp=" + dscp + " and logtime between '" + timeStartStr + "' and '" + timeEndStr + "' "
	seelog.Info("[func:/api/ping.json] sql: ", querySql)
	rows, err := db.Query(querySql)
	seelog.Debug("[func:/api/ping.json] Query ", querySql)
	if err != nil {
		seelog.Error("[func:/api/ping.json] Query ", err)
	} else {
		for rows.Next() {
			l := new(g.PingLog)
			err := rows.Scan(&l.Logtime, &l.Maxdelay, &l.Mindelay, &l.Avgdelay, &l.Losspk, &l.TcpDelay, &l.UdpDelay, &l.IcmpDelay)
			if err != nil {
				seelog.Error("[/api/ping.json] Rows", err)
				continue
			}
			for n, v := range lastcheck {
				if v[:16] == l.Logtime[:16] {
					maxdelay[n] = l.Maxdelay
					mindelay[n] = l.Mindelay
					avgdelay[n] = l.Avgdelay
					losspk[n] = l.Losspk
					tcpdelay[n] = l.TcpDelay
					udpdelay[n] = l.UdpDelay
					icmpdelay[n] = l.IcmpDelay
					break
				}
			}
		}
		rows.Close()
	}
	preout := map[string][]string{
		"lastcheck": lastcheck,
		"maxdelay":  maxdelay,
		"mindelay":  mindelay,
		"avgdelay":  avgdelay,
		"losspk":    losspk,
		"TcpDelay":  tcpdelay,
		"UdpDelay":  udpdelay,
		"IcmpDelay": icmpdelay,
	}
	w.Header().Set("Content-Type", "application/json")
	RenderJson(w, preout)
}

func configApiRoutes() {
	http.HandleFunc("/api/config.json", func(w http.ResponseWriter, r *http.Request) {
		// if !AuthUserIp(r.RemoteAddr) && !AuthAgentIp(r.RemoteAddr, true) {
		// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
		// 	http.Error(w, o, 401)
		// 	return
		// }
		r.ParseForm()
		nconf := g.Config{}
		cfgJson, _ := json.Marshal(g.Cfg)
		// seelog.Info("[func:/api/config.json] ", string(cfgJson))
		json.Unmarshal(cfgJson, &nconf)
		// nconf.Password = ""
		// if !AuthAgentIp(r.RemoteAddr, false) {
		// 	if nconf.Alert["SendEmailPassword"] != "" {
		// 		nconf.Alert["SendEmailPassword"] = "samepasswordasbefore"
		// 	}
		// }
		//fmt.Print(g.Cfg.Alert["SendEmailPassword"])
		onconf, _ := json.Marshal(nconf)
		var out bytes.Buffer
		json.Indent(&out, onconf, "", "\t")
		o := out.String()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, o)
	})

	//Ping画图
	http.HandleFunc("/api/graph.png", func(w http.ResponseWriter, r *http.Request) {
		// if !AuthUserIp(r.RemoteAddr) {
		// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
		// 	http.Error(w, o, 401)
		// 	return
		// }
		w.Header().Set("Content-Type", "image/png")
		r.ParseForm()
		if len(r.Form["g"]) == 0 {
			GraphText(83, 70, "GET PARAM ERROR").Save(w)
			return
		}
		url := r.Form["g"][0]
		config := g.PingStMini{}
		// timeout := time.Duration(time.Duration(g.Cfg.Base["Timeout"]) * time.Second)
		client := http.Client{
			Timeout: 50 * time.Second,
		}
		resp, err := client.Get(url)
		if err != nil {
			seelog.Info("[func:/api/graph.png] ", err)
			GraphText(80, 70, "REQUEST API ERROR").Save(w)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == 401 {
			GraphText(80, 70, "401-UNAUTHORIZED").Save(w)
			return
		}
		if resp.StatusCode != 200 {
			GraphText(85, 70, "ERROR CODE "+strconv.Itoa(resp.StatusCode)).Save(w)
			return
		}
		body, err := ioutil.ReadAll(resp.Body)
		err = json.Unmarshal(body, &config)
		if err != nil {
			GraphText(80, 70, "PARSE DATA ERROR").Save(w)
			return
		}
		Xals := []float64{}
		AvgDelay := []float64{}
		LossPk := []float64{}
		Bkg := []float64{}
		MaxDelay := 0.0
		for i := 0; i < len(config.LossPk); i = i + 1 {
			avg, _ := strconv.ParseFloat(config.AvgDelay[i], 64)
			if MaxDelay < avg {
				MaxDelay = avg
			}
			AvgDelay = append(AvgDelay, avg)
			losspk, _ := strconv.ParseFloat(config.LossPk[i], 64)
			LossPk = append(LossPk, losspk)
			Xals = append(Xals, float64(i))
			Bkg = append(Bkg, 100.0)
		}
		// seelog.Debug("[/api/graph.png] g parameter: ", r.Form["g"])
		// seelog.Debug("[/api/graph.png] Remote response: ", string(body))
		// seelog.Debug("[/api/graph.png] Xals: ", Xals, "\n AvgDelay: ", AvgDelay, "\n LossPk: ", LossPk)
		// seelog.Debug("[/api/graph.png] MaxDelay: ", MaxDelay)
		graph := chart.Chart{
			Width:  300 * 3,
			Height: 130 * 3,
			Background: chart.Style{
				FillColor: drawing.Color{249, 246, 241, 255},
			},
			XAxis: chart.XAxis{
				Style: chart.Style{
					Show:     true,
					FontSize: 20,
				},
				TickPosition: chart.TickPositionBetweenTicks,
				ValueFormatter: func(v interface{}) string {
					return config.Lastcheck[int(v.(float64))][11:16]
				},
			},
			YAxis: chart.YAxis{
				Style: chart.Style{
					Show:     true,
					FontSize: 20,
				},
				Range: &chart.ContinuousRange{
					Min: 0.0,
					Max: 100.0,
				},
				ValueFormatter: func(v interface{}) string {
					if vf, isFloat := v.(float64); isFloat {
						return fmt.Sprintf("%0.0f", vf)
					}
					return ""
				},
			},
			YAxisSecondary: chart.YAxis{
				//NameStyle: chart.StyleShow(),
				Style: chart.Style{
					Show:     true,
					FontSize: 20,
				},
				Range: &chart.ContinuousRange{
					Min: 0.0,
					Max: MaxDelay + MaxDelay/10,
				},
				ValueFormatter: func(v interface{}) string {
					if vf, isFloat := v.(float64); isFloat {
						return fmt.Sprintf("%0.000f", vf)
					}
					return ""
				},
			},
			Series: []chart.Series{
				chart.ContinuousSeries{
					Style: chart.Style{
						Show:        true,
						StrokeColor: drawing.Color{249, 246, 241, 255},
						FillColor:   drawing.Color{249, 246, 241, 255},
					},
					XValues: Xals,
					YValues: Bkg,
				},
				chart.ContinuousSeries{
					Style: chart.Style{
						Show:        true,
						StrokeColor: drawing.Color{0, 204, 102, 200},
						FillColor:   drawing.Color{0, 204, 102, 200},
					},
					XValues: Xals,
					YValues: AvgDelay,
					YAxis:   chart.YAxisSecondary,
				},
				chart.ContinuousSeries{
					Style: chart.Style{
						Show:        true,
						StrokeColor: drawing.Color{255, 0, 0, 200},
						FillColor:   drawing.Color{255, 0, 0, 200},
					},
					XValues: Xals,
					YValues: LossPk,
				},
			},
		}
		graph.Render(chart.PNG, w)
	})

	//代理访问
	http.HandleFunc("/api/proxy.json", func(w http.ResponseWriter, r *http.Request) {
		// if !AuthUserIp(r.RemoteAddr) {
		// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
		// 	http.Error(w, o, 401)
		// 	return
		// }
		w.Header().Set("Content-Type", "application/json")
		r.ParseForm()
		if len(r.Form["g"]) == 0 {
			o := "Url Param Error!"
			http.Error(w, o, 406)
			return
		}
		// to := strconv.Itoa(g.Cfg.Base["Timeout"])
		// if len(r.Form["t"]) > 0 {
		// 	to = r.Form["t"][0]
		// }
		url := strings.Replace(strings.Replace(r.Form["g"][0], "%26", "&", -1), " ", "%20", -1)
		// defaultto, err := strconv.Atoi(to)
		var err error
		if err != nil {
			o := "Timeout Param Error!"
			http.Error(w, o, 406)
			return
		}
		// timeout := time.Duration(time.Duration(defaultto) * time.Second)
		client := http.Client{
			Timeout: 5 * time.Second,
		}
		resp, err := client.Get(url)
		if err != nil {
			o := "Request Remote Data Error:" + err.Error()
			http.Error(w, o, 503)
			return
		}
		defer resp.Body.Close()
		resCode := resp.StatusCode
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			o := "Read Remote Data Error:" + err.Error()
			http.Error(w, o, 503)
			return
		}
		if resCode != 200 {
			o := "Get Remote Data Status Error"
			http.Error(w, o, resCode)
		}
		var out bytes.Buffer
		json.Indent(&out, body, "", "\t")
		o := out.String()
		fmt.Fprintln(w, o)
	})

	//Ping拓扑API
	http.HandleFunc("/api/topology.json", func(w http.ResponseWriter, r *http.Request) {
		// if !AuthUserIp(r.RemoteAddr) && !AuthAgentIp(r.RemoteAddr, true) {
		// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
		// 	http.Error(w, o, 401)
		// 	return
		// }
		preout := make(map[string]string)
		for _, v := range g.SelfCfg.Ping {
			// preout[v["Addr"]] = "true"
			// check the status of every neighbor node
			if funcs.CheckAlertStatus(v) {
				preout[v["Addr"]] = "true"
			} else {
				preout[v["Addr"]] = "false"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		RenderJson(w, preout)
	})
}

func GraphText(x int, y int, txt string) chart.Renderer {
	f, _ := chart.GetDefaultFont()
	rhart, _ := chart.PNG(300, 130)
	chart.Draw.Text(rhart, txt, x, y, chart.Style{
		FontColor: drawing.ColorBlack,
		FontSize:  10,
		Font:      f,
	})
	return rhart
}

func StartHttp() {
	// Parse command line arguments for port number
	// if len(os.Args) < 2 {
	// 	fmt.Println("Usage: go run http.go <port>")
	// 	os.Exit(1)
	// }

	// port := os.Args[1]
	port := "8889"

	// Register HTTP handler
	http.HandleFunc("/api/ping.json", handleRequest)
	configApiRoutes()
	configIndexRoutes()

	// Start HTTP server
	seelog.Info("[func:StartHttp] starting to listen on ", port)
	fmt.Printf("Starting server at port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Println(err)
	}
}

func main() {
	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	ready := false

	procName := os.Getenv("PROC_NAME")
	seelog.Info("[func:main] procName: ", procName)
	setProcName(procName)
	// seelog.Info(os.Getenv("PROC_NAME"))

	g.Point_index = 0
	var index int
	if _, err := fmt.Sscanf(procName, "point-%d", &index); err != nil {
		seelog.Error("[func:main] 无法解析 PROC_NAME: %v", err)
	}
	g.Point_index = index
	g.ParseConfig()
	// seelog.Info("[func:main] g.Point_index: ", g.Point_index)
	// attach_bpf()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		cond.L.Lock()
		for !ready {
			cond.Wait() // 等待条件满足
		}
		cond.L.Unlock()
		send.Init()
		c := cron.New()
		c.AddFunc("*/20 * * * * *", func() {
			go send.Send()
		}, "ping")
		c.Start()
		StartHttp()
	}()

	go func() {
		Agentgrpc()
		cond.L.Lock()
		ready = true
		cond.Broadcast() // 通知所有等待的 goroutine
		cond.L.Unlock()
	}()

	for {
		select {
		case <-sig: // 如果接收到退出信号
			seelog.Info("[func:main] Received interrupt signal, shutting down...")
			if g.Cfg.PingConfig.Clean {
				send.PingClean()
			}
			return
		}
	}
}

func RenderJson(w http.ResponseWriter, v interface{}) {
	bs, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Write(bs)
}

func configIndexRoutes() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// if !AuthUserIp(r.RemoteAddr) {
		// 	o := "Your ip address (" + r.RemoteAddr + ")  is not allowed to access this site!"
		// 	http.Error(w, o, 401)
		// 	return
		// }
		seelog.Info("Handling home page……")
		if strings.HasSuffix(r.URL.Path, "/") {
			// TODO: "C:\Users\ty21_\Downloads\Zonemesh\agent" is a hardcoded string
			if !g.IsExist(filepath.Join(g.GetRoot(), "/html", r.URL.Path, "index.html")) {
				seelog.Error("Don't find index.html")
				http.NotFound(w, r)
				return
			}
		}
		http.FileServer(http.Dir(filepath.Join(g.GetRoot(), "/html"))).ServeHTTP(w, r)
	})

}

// func setProcName(name string) {
//     b := append([]byte(name), 0) // null-terminated
//     syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_NAME,
//         uintptr(unsafe.Pointer(&b[0])), 0, 0, 0)
// }

func setProcName(name string) error {
	b := append([]byte(name), 0) // null-terminated string
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		uintptr(syscall.PR_SET_NAME),
		uintptr(unsafe.Pointer(&b[0])),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
