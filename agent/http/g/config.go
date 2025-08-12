package g

import (

	// "pingLog/sql"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"

	// "io"
	"io/ioutil"
	"log"

	// "net/http"
	"os"
	"path/filepath"

	// "strconv"
	"strings"

	// "sync"
	// "time"
	"github.com/cihub/seelog"
)

var (
	Root        string
	Cfg         Config
	Point_index int		// begin from 1
	// CLock	       sync.Mutex
	SelfCfg     NetworkMember
	AlertStatus map[string]bool
	// AuthUserIpMap  map[string]bool
	// AuthAgentIpMap map[string]bool
	// ToolLimit map[string]int
	Db *sql.DB

// DLock          sync.Mutex
)

func IsExist(fp string) bool {
	_, err := os.Stat(fp)
	return err == nil || os.IsExist(err)
}

func ReadConfig(filename string) Config {
	config := Config{}
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		log.Fatal("Config Not Found!")
	} else {
		err = json.NewDecoder(file).Decode(&config)
		if err != nil {
			log.Fatal(err)
		}
	}
	// fmt.Println("name: ", config.Name)
	// fmt.Println("destinations: ", config.Destinations)
	return config
}

func GetRoot() string {
	// return "D:\\gopath\\Zonemesh\\agent"
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal("Get Root Path Error:", err)
	}
	dirctory := strings.Replace(dir, "\\", "/", -1)
	runes := []rune(dirctory)
	l := strings.LastIndex(dirctory, "http") - 1
	if l > len(runes) {
		l = len(runes)
	}
	// seelog.Info("Root: ", string(runes[0:l]))
	// return ""../Zonemesh"
	return string(runes[0:l])
}

func ParseConfig() {
	Root = GetRoot()
	// seelog.Info("Root: ", Root)
	// cofig file path
	cfile := Root + "/conf/config.json"
	if Point_index != 0 {
		cfile = Root + "/conf/containers/point-" + strconv.Itoa(Point_index) + ".json"
	}
	fmt.Println("[ParseConfig] config file: ", cfile)
	// if !IsExist(Root + "/conf/" + "config.json") {
	// 	if !IsExist(Root + "/conf/" + "config-base.json") {
	// 		log.Fatalln("[Fault]config file:", Root+"/conf/"+"config(-base).json", "both not existent.")
	// 	}
	// 	cfile = "config-base.json"
	// }
	// _, err := seelog.LoggerFromConfigAsFile(Root + "/agent/http/seelog.xml")

	logger, err := seelog.LoggerFromConfigAsFile(Root + "/http/seelog.xml")
	if err != nil {
		log.Fatalln("[Fault]log config open fail .", err)
	}
	seelog.ReplaceLogger(logger)
	// Cfg = ReadConfig(Root + "/conf/" + cfile)
	Cfg = ReadConfig(cfile)
	if Cfg.Name == "" {
		Cfg.Name, _ = os.Hostname()
	}
	if Cfg.Addr == "" {
		Cfg.Addr = "127.0.0.1"
	}
	// Cfg.Ver = ver
	// if !IsExist("../db/" + "pingLog.db") {
	// 	if !IsExist("../db/" + "pingLog-base.db") {
	// 		log.Fatalln("[Fault]db file:", Root+"/db/"+"pingLog(-base).db", "both not existent.")
	// 	}
	// 	src, err := os.Open("../db/" + "pingLog-base.db")
	// 	if err != nil {
	// 		log.Fatalln("[Fault]db-base file open error.")
	// 	}
	// 	defer src.Close()
	// 	dst, err := os.OpenFile(Root+"/db/"+"pingLog.db", os.O_WRONLY|os.O_CREATE, 0644)
	// 	if err != nil {
	// 		log.Fatalln("[Fault]db-base file copy error.")
	// 	}
	// 	defer dst.Close()
	// 	io.Copy(dst, src)
	// }
	seelog.Info("Config loaded")
	Db, err = sql.Open("sqlite3", Root+"/database/pingLog.db")
	if err != nil {
		log.Fatalln("[Fault]db open fail .", err)
	}
	SelfCfg = Cfg.Network[Cfg.Addr]
	AlertStatus = map[string]bool{}
	// ToolLimit = map[string]int{}
	// saveAuth()
}

// func SaveCloudConfig(url string) (Config, error) {
// 	config := Config{}
// 	timeout := time.Duration(5 * time.Second)
// 	client := http.Client{
// 		Timeout: timeout,
// 	}
// 	resp, err := client.Get(url)
// 	if err != nil {
// 		return config, err
// 	}
// 	defer resp.Body.Close()
// 	body, err := ioutil.ReadAll(resp.Body)
// 	err = json.Unmarshal(body, &config)
// 	if err != nil {
// 		config.Name = string(body)
// 		return config, err
// 	}
// 	Name := Cfg.Name
// 	Addr := Cfg.Addr
// 	Ver := Cfg.Ver
// 	Password := Cfg.Password
// 	Port := Cfg.Port
// 	Endpoint := Cfg.Mode["Endpoint"]
// 	Cfg = config
// 	Cfg.Name = Name
// 	Cfg.Addr = Addr
// 	Cfg.Ver = Ver
// 	Cfg.Port = Port
// 	Cfg.Password = Password
// 	Cfg.Mode["LastSuccTime"] = time.Now().Format("2006-01-02 15:04:05")
// 	Cfg.Mode["Status"] = "true"
// 	Cfg.Mode["Endpoint"] = Endpoint
// 	Cfg.Mode["Type"] = "cloud"
// 	SelfCfg = Cfg.Network[Cfg.Addr]
// 	saveAuth()
// 	return config, nil
// }

func SaveConfig() error {
	Root = GetRoot()
	seelog.Info("Root: ", Root)
	// cofig file path
	cfile := Root + "/conf/config.json"
	if Point_index != 0 {
		cfile = Root + "/conf/containers/point-" + strconv.Itoa(Point_index) + ".json"
	}
	// saveAuth()
	rrs, _ := json.Marshal(Cfg)
	var out bytes.Buffer
	errjson := json.Indent(&out, rrs, "", "\t")
	if errjson != nil {
		seelog.Error("[func:SaveConfig] Json Parse ", errjson)
		return errjson
	}

	err := ioutil.WriteFile(cfile, []byte(out.String()), 0644)
	if err != nil {
		seelog.Error("[func:SaveConfig] Config File Write", err)
		return err
	}
	return nil
}

// func saveAuth() {
// 	AuthUserIpMap = map[string]bool{}
// 	AuthAgentIpMap = map[string]bool{}
// 	for _, k := range Cfg.Network {
// 		AuthAgentIpMap[k.Addr] = true
// 	}
// 	Cfg.Authiplist = strings.Replace(Cfg.Authiplist, " ", "", -1)
// 	if Cfg.Authiplist != "" {
// 		authiplist := strings.Split(Cfg.Authiplist, ",")
// 		for _, ip := range authiplist {
// 			AuthUserIpMap[ip] = true
// 		}
// 	}
// }
