package rdp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/png"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SkillfulCarving/go-rdp/core"
	"github.com/SkillfulCarving/go-rdp/protocol/nla"
	"github.com/SkillfulCarving/go-rdp/protocol/pdu"
	"github.com/SkillfulCarving/go-rdp/protocol/sec"
	"github.com/SkillfulCarving/go-rdp/protocol/t125"
	"github.com/SkillfulCarving/go-rdp/protocol/tpkt"
	"github.com/SkillfulCarving/go-rdp/protocol/x224"
)

const (
	HexDataFirst  = "0300002f2ae00000000000436f6f6b69653a206d737473686173683d4445534b544f502d470d0a010008000b000000"
	HexDataSecond = "3037a003020106a130302e302ca02a04284e544c4d5353500001000000b78208e2000000000000000000000000000000000a00614a0000000f"
	HexDataXRdp   = "0300000b06e00000000000"
)

var (
	NtlmInfo = map[int]string{
		0x001: "NetBIOS computer name",
		0x002: "NetBIOS domain name",
		0x003: "DNS computer name",
		0x004: "DNS domain name",
	}
)

type Banner struct {
	Hostname string
	OSInfo   string
	NtlmInfo string
}

func (b Banner) String() string {
	return fmt.Sprintf("Hostname: %v\nOS: %v\n%v", b.Hostname, b.OSInfo, b.NtlmInfo)
}

type Client struct {
	addr           string
	timeout        time.Duration
	username       string
	password       string
	domain         string
	screenshot     bool
	screenshotTime int
	Picture
	Banner
}

type Picture struct {
	Height int
	Width  int
	Path   string
}

func NewClient(addr string, timeout time.Duration, options ...func(*Client)) *Client {
	c := &Client{
		addr:    addr,
		timeout: timeout,
	}
	for _, o := range options {
		o(c)
	}
	return c
}

func WithAuth(user, pass string) func(client *Client) {
	return func(client *Client) {
		client.username = user
		client.password = pass
	}
}

func WithDomain(domain string) func(client *Client) {
	return func(client *Client) {
		client.domain = domain
	}
}

func WithScreenshot(picture Picture, timeout ...int) func(client *Client) {
	return func(client *Client) {
		client.screenshot = true
		client.screenshotTime = 10 //默认为10s
		if picture.Width == 0 || picture.Height == 0 {
			picture.Width = 1920
			picture.Height = 1080
			picture.Path = strings.ReplaceAll(client.addr, ":", "_") + ".png"
		}
		client.Picture = picture
		if len(timeout) > 0 {
			client.screenshotTime = timeout[0]
		}
	}
}

func (c *Client) IsXRdp() bool {
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second * 2))
	defer conn.Close()
	dataXRdp, _ := hex.DecodeString(HexDataXRdp)
	_, _ = conn.Write(dataXRdp)
	buf := make([]byte, 1000)
	n, err := conn.Read(buf)
	if hex.EncodeToString(buf[:n]) == "0300000902f0802180" {
		return true
	}
	return false
}

func (c *Client) GetBanner() (banner Banner) {
	defer func() {
		recover()
	}()
	dataFirst, _ := hex.DecodeString(HexDataFirst)
	dataSecond, _ := hex.DecodeString(HexDataSecond)

	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)

	if err != nil {
		conn, err = net.DialTimeout("tcp", c.addr, c.timeout)
		if err != nil {
			return
		}
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second * 2))
	defer conn.Close()

	buf := make([]byte, 1000)
	_, _ = conn.Write(dataFirst)
	n, err := conn.Read(buf)
	if err != nil && !bytes.HasPrefix(buf[:n], []byte{3, 0, 0}) {
		return
	}
	conn = tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	n, err = conn.Write(dataSecond)
	if err != nil {
		return
	}
	n, err = conn.Read(buf)
	if err != nil {
		return
	}
	// 数据从NTLMSSP开始
	splitDat := bytes.Split(buf[:n], []byte{78, 84, 76, 77, 83, 83, 80, 0})
	if len(splitDat) > 1 {
		newBuf := buf[len(splitDat[0]):n]

		//名称长度 12-13 偏移量
		nameLen := int(binary.LittleEndian.Uint16(newBuf[12:14]))
		nameOff := int(binary.LittleEndian.Uint32(newBuf[16:20]))

		// 获取设备名称信息
		banner.Hostname = formatData(newBuf[nameOff : nameOff+nameLen])

		// 获取协议信息
		ntlm := formatData(newBuf[:8]) + "[*]"

		// Target 获取数据信息
		tgLen := int(binary.LittleEndian.Uint16(newBuf[40:42]))
		tgOff := int(binary.LittleEndian.Uint16(newBuf[44:48]))

		tgInfo := newBuf[tgOff : tgLen+tgOff]

		// 34*i 34为字节大小， 前两个字节为长度
		for i := 0; i < tgLen; i++ {
			if tgLen < 34*i {
				break
			}
			// 当前位置
			site := 34 * i
			tgType := int(binary.LittleEndian.Uint16(tgInfo[site : site+2])) // 类型
			if _, ok := NtlmInfo[tgType]; ok {
				dLen := int(binary.LittleEndian.Uint16(tgInfo[site+2 : site+4])) // 长度
				ntlm += "\n\t[-] " + NtlmInfo[tgType] + ": " + formatData(tgInfo[site+4:site+4+dLen])
			}
		}
		banner.NtlmInfo = ntlm
		// 获取系统信息 info 48-56
		banner.OSInfo = getOsInfo(newBuf[48:56])
	}
	c.Banner = banner
	return banner
}

func (c *Client) Login() bool {
	defer func() {
		recover()
	}()
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	Gtpkt := tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(c.domain, c.username, c.password))
	Gx224 := x224.New(Gtpkt)
	Gmcs := t125.NewMCSClient(Gx224)
	Gsec := sec.NewClient(Gmcs)
	Gpdu := pdu.NewClient(Gsec)
	Gchannels := core.NewChannels(Gsec)

	Gmcs.SetClientCoreData(uint16(1920), uint16(1080))

	Gsec.SetUser(c.username)
	Gsec.SetPwd(c.password)
	Gsec.SetDomain(c.domain)

	Gtpkt.SetFastPathListener(Gsec)
	Gsec.SetFastPathListener(Gpdu)
	Gsec.SetChannelSender(Gmcs)
	Gchannels.SetChannelSender(Gsec)

	err = Gx224.Connect()
	if err != nil {
		return false
	}
	success := <-Gtpkt.Success
	if !success {
		return false
	}
	if !c.screenshot {
		return true
	}
	ScreenImage := image.NewRGBA(image.Rect(0, 0, 1920, 1080))
	Gpdu.On("update", func(rectangles []pdu.RgbColor) {
		for _, v := range rectangles {
			ScreenImage.Set(v.X, v.Y, v.Color)
		}
	})
	time.Sleep(time.Duration(c.screenshotTime) * time.Second)
	buff := bytes.NewBuffer([]byte{})

	_ = png.Encode(buff, ScreenImage)
	_ = os.WriteFile(c.Path, buff.Bytes(), 0666)
	return true
}

func formatData(d []byte) string {
	hexData := strings.Replace(hex.EncodeToString(d), "00", "", -1)
	newData, err := hex.DecodeString(hexData)
	if err != nil {
		return ""
	}
	return string(newData)
}

// 获取系统信息
func getOsInfo(d []byte) string {
	var systemInfo string
	major := int(d[0])
	minor := int(d[1])
	build := int(binary.LittleEndian.Uint16(d[2:4]))
	System := ""
	if major == 10 {
		if build >= 22000 {
			System = "Windows 11"
		} else {
			System = "Windows 10"
		}
	}
	if major == 6 {
		if minor > 1 {
			System = "Windows 8.1/Windows Server 2012 R2"
		} else {
			System = "Windows 7"
		}
	}
	systemInfo = fmt.Sprintf("%v.%v Build %v", System, minor, build)
	if major == 5 {
		System = "Windows XP"
		systemInfo = fmt.Sprintf("%v Build %v", System, build)
	}
	return systemInfo
}
