package g

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	Root string
	Topo []Topology
	TopoFile string
)

func GetRoot() string {
	// return "D:\\gopath\\Zonemesh\\controller"
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal("Get Root Path Error:", err)
	}
	dirctory := strings.Replace(dir, "\\", "/", -1)
	runes := []rune(dirctory)
	l := strings.LastIndex(dirctory, "server") - 1
	if l > len(runes) {
		l = len(runes)
	}
	log.Println("Root: ", string(runes[0:l]))
	// seelog.Info("Root: ", string(runes[0:l]))
	return string(runes[0:l])
}

func ParseTopo(filename string) {
	Root = GetRoot()
	TopoFile = Root + "/conf/" + filename
	file, err := os.Open(TopoFile)
	if err != nil {
		log.Fatal("Open Topo File Error:", err)
	}
	defer file.Close()

	err = json.NewDecoder(file).Decode(&Topo)
	if err != nil {
		log.Fatal("Parse Topo File Error:", err)
	}
	return
}

