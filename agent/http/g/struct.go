package g

type PingLog struct {
	Logtime  string
	Dscp     int
	Maxdelay string
	Mindelay string
	Avgdelay string
	Losspk   string
	TcpDelay string
	UdpDelay string
	IcmpDelay string
}

type Config struct {
	Addr           string			`json:"Addr"`
	Addr6		   string			`json:"Addr6"`
	Name           string			`json:"Name"`
	Destinations   []string			`json:"Destinations"`
	Destinations6  []string			`json:"Destinations6"`
	ControllerAddr string			`json:"ControllerAddr"`
	ControllerAddr6 string			`json:"ControllerAddr6"`
	// ControllerPort int	    	`json:"ControllerPort"`
	Port           int	    		`json:"Port"`
	Dscp           []int			`json:"Dscp"`
	PingConfig     PingTaskConfig	`json:"PingConfig"`
	Policies	   []Policy			`json:"Policies"`
	UseIPv6        bool				`json:"UseIPv6"`
	Mode           map[string]string	`json:"Mode"`
	Base           map[string]int		`json:"Base"`
	Topology       map[string]string		`json:"Topology"`
	Network        map[string]NetworkMember	`json:"Network"`
	// Ver  string
	// Alert      map[string]string
	// Chinamap   map[string]map[string][]string
	// Toollimit  int
	// Authiplist string
	// Password   string
}

type Policy struct {
	List 		[]int
	Index 		[]int
	Algorithm   []int
	Color       int
	Preference  int
}

type NetworkMember struct {
	Name     string
	Addr     string
	Addr6    string
	Zonemesh bool
	Ping     []map[string]string
	//Tools map[string][]string
	Topology []map[string]string
}

// Ping mini graph Struct
type PingStMini struct {
	Lastcheck []string `json:"lastcheck"`
	LossPk    []string `json:"losspk"`
	AvgDelay  []string `json:"avgdelay"`
}

// Ping Struct
type PingSt struct {
	SendPk   int
	RevcPk   int
	LossPk   int
	MinDelay float64
	AvgDelay float64
	MaxDelay float64
}

// PingTaskConfig Struct
type PingTaskConfig struct {
	Epoch       int `json:"epoch"`       // 间隔时间
	Count       int `json:"count"`       // ping个数
	Connections int `json:"connections"` // 保持的连接数
	Clean     	bool `json:"clean"`       // 是否清理旧数据
}
