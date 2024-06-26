package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/smtp"
	"os"
	"strings"
)

var config = &struct {
	Subject       string
	Raw           string
	Body          string
	Bodyfile      string
	Headers       vari
	Ins           bool
	TLS           bool
	STLS          bool
	Authid        string
	Authusr       string
	Authpwd       string
	Authcrammd5   string
	Fuck          bool
	Name          string
	From          string
	Localhost     string
	To            string
	Local         string
	Server        string
	ServerName    string
	TlsServerName string
	IPv6          bool
	IPv6Zone      string
	Network       string
}{}

type vari []string

func (p *vari) String() string {
	return strings.Join(*p, " ")
}

func (p *vari) Set(v string) error {
	*p = append(*p, v)
	return nil
}

func init() {
	flag.StringVar(&config.Subject, "subject", "", "邮件主题")
	flag.StringVar(&config.Raw, "raw", "", "指定文件作为整个邮件的报文")
	flag.StringVar(&config.Body, "body", "", "邮件正文")
	flag.StringVar(&config.Bodyfile, "bodyfile", "", "正文文件(连接在body后)")
	flag.Var(&config.Headers, "header", "自定义头部")
	flag.BoolVar(&config.Ins, "ins", false, "TLS InsecureSkipVerify")
	flag.BoolVar(&config.TLS, "tls", false, "启用TLS传输")
	flag.BoolVar(&config.STLS, "stls", false, "启用STARTTLS")
	flag.StringVar(&config.Authid, "authid", "", "PlainAuth identity")
	flag.StringVar(&config.Authusr, "authusr", "", "PlainAuth username")
	flag.StringVar(&config.Authpwd, "authpwd", "", "PlainAuth password")
	flag.StringVar(&config.Authcrammd5, "crammd5", "", "CRAMMD5Auth secret")
	flag.BoolVar(&config.Fuck, "fuck", false, "允许未经任何TLS的认证")
	flag.StringVar(&config.Name, "name", "", "指定发件人名称, 缺省: 发件人@前的内容")
	flag.StringVar(&config.From, "from", "", "发件人")
	flag.StringVar(&config.Localhost, "localhost", "", `指定发件服务器名称, 缺省: 发件人@后的主机名`)
	flag.StringVar(&config.To, "to", "", "收件人")
	flag.StringVar(&config.Local, "local", "", "bind addr")
	flag.StringVar(&config.Server, "server", "", `收件人<服务器名称/IP地址>:<端口>, 缺省: 收件人@后的主机名进行MX解析结果以及25端口, 常见smtp端口有25 587 465 2525`)
	flag.StringVar(&config.ServerName, "servername", "", `指定收件服务器名称, 缺省: -server中的主机名`)
	flag.StringVar(&config.TlsServerName, "tlsservername", "", `指定TLS认证时使用的服务器名称, 缺省: ServerName`)
	flag.BoolVar(&config.IPv6, "6", false, "使用IPv6")
	flag.StringVar(&config.IPv6Zone, "zone", "", "IPv6 scoped addressing zone")
	usage := flag.Usage
	flag.Usage = func() {
		usage()
		println()
		println(`e.g.`)
		println(" "+os.Args[0], `-tls -subject hello -body world -from root@localhost -to root@localhost -authusr xxxx -authpwd xxxx`)
	}
	flag.Parse()

	if config.From == "" {
		flag.Usage()
		os.Exit(1)
	}

	if config.To == "" {
		flag.Usage()
		os.Exit(1)
	}

	if f := strings.Split(config.From, "@"); len(f) != 2 {
		log.Println("`from' 的格式为 name@host")
		flag.Usage()
		os.Exit(1)
	} else {
		if config.Name == "" {
			config.Name = f[0]
		}
		if config.Localhost == "" {
			config.Localhost = f[1]
		}
	}

	if f := strings.Split(config.To, "@"); len(f) != 2 {
		log.Println("`to' 的格式为 name@host")
		flag.Usage()
		os.Exit(1)
	} else {
		var raw_host = f[1]
		var service_or_port = "25"
		var incomplete = false

		if config.Server != "" {
			if host, port, e := net.SplitHostPort(config.Server); e != nil {
				log.Println(e.Error()+",", "use it as hostname")
				log.Println("host specification only,", config.Server)
				raw_host = config.Server
				incomplete = true
			} else {
				if host == "" && port != "" {
					log.Println("port specification only,", port)
					service_or_port = port
					incomplete = true
				} // any thing else ?
			}
		}

		if config.Server == "" || incomplete {
			if ip := net.ParseIP(raw_host); ip != nil {
				if ip.To4() != nil {
					log.Println("server is IPv4:", ip.String())
					config.Server = ip.String() + ":" + service_or_port
				} else {
					log.Println("server is IPv6:", ip.String())
					config.Server = "[" + ip.String() + "]:" + service_or_port
				}
			} else if mx, e := net.LookupMX(raw_host); e != nil {
				log.Println("MX lookup failed:", e.Error())
				os.Exit(1)
			} else {
				var pref uint32 = 1 << 16
				var name string
				for i, v := range mx { // get pref
					log.Println("MX record", i, "for", raw_host+":", v.Host, "pref", v.Pref)
					if v.Host != "" && !(pref < uint32(v.Pref)) { // lol
						pref = uint32(v.Pref)
						name = v.Host
					}
				}

				/*if len(name) > 0 && name[len(name)-1] == '.' { // strip dot from tail
					name = name[:len(name)-1]
				}*/

				if len(name) > 0 {
					log.Println("pref MX host:", name)
					config.Server = name + ":" + service_or_port
				} else {
					log.Println("MX lookup failed: blank pref MX host")
					os.Exit(1)
				}
			}
		}
	}

	log.Println("final server addr:", config.Server)

	if host, _, e := net.SplitHostPort(config.Server); e != nil {
		log.Println(e.Error())
		os.Exit(1)
	} else {
		if config.ServerName == "" {
			config.ServerName = host
		}

		if config.TlsServerName == "" {
			config.TlsServerName = config.ServerName
		}
	}

	if config.IPv6 {
		config.Network = "tcp6"
	} else {
		config.Network = "tcp4"
	}
}

type plainAuth struct {
	fuck                         bool
	identity, username, password string
}

func PlainAuth(fuck bool, identity, username, password string) smtp.Auth {
	return &plainAuth{fuck, identity, username, password}
}

func (a *plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !a.fuck && !server.TLS {
		return "", nil, errors.New("Fuck, we are not tls")
	}
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// We've already sent everything.
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type cramMD5Auth struct {
	fuck             bool
	username, secret string
}

func CRAMMD5Auth(fuck bool, username, secret string) smtp.Auth {
	return &cramMD5Auth{fuck, username, secret}
}

func (a *cramMD5Auth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !a.fuck && !server.TLS {
		return "", nil, errors.New("Fuck, we are not tls")
	}
	return "CRAM-MD5", nil, nil
}

func (a *cramMD5Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		d := hmac.New(md5.New, []byte(a.secret))
		d.Write(fromServer)
		s := make([]byte, 0, d.Size())
		return []byte(a.username + " " + hex.EncodeToString(d.Sum(s))), nil
	}
	return nil, nil
}

func main() {
	var e error
	var laddr, raddr *net.TCPAddr
	var conn net.Conn
	if config.Local != "" {
		laddr, e = net.ResolveTCPAddr(config.Network, config.Local)
		if e != nil {
			log.Fatal(e.Error())
		}
	}
	raddr, e = net.ResolveTCPAddr(config.Network, config.Server)
	if e != nil {
		log.Fatal(e.Error())
	}

	raddr.Zone = config.IPv6Zone

	conn, e = net.DialTCP(config.Network, laddr, raddr)
	if e != nil {
		log.Fatal(e.Error())
	}
	if config.TLS {
		if config.TlsServerName != "" {
			conn = tls.Client(conn, &tls.Config{ServerName: config.TlsServerName, InsecureSkipVerify: config.Ins})
		} else {
			conn = tls.Client(conn, &tls.Config{ServerName: config.ServerName, InsecureSkipVerify: config.Ins})
		}
		if e = conn.(*tls.Conn).Handshake(); e != nil {
			log.Fatal(e.Error())
		}
	}
	defer conn.Close()
	c, e := smtp.NewClient(conn, config.ServerName) // MX(Mail Exchanger): nslookup -querytype=mx xx.com
	if e != nil {
		log.Fatal(e.Error())
	}
	defer c.Close()
	defer c.Quit()

	e = c.Hello(config.Localhost) // aahhhh.org
	if e != nil {
		log.Println(e.Error())
		return
	}

	if config.STLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if config.TlsServerName != "" {
				e = c.StartTLS(&tls.Config{ServerName: config.TlsServerName, InsecureSkipVerify: config.Ins})
			} else {
				e = c.StartTLS(&tls.Config{ServerName: config.ServerName, InsecureSkipVerify: config.Ins})
			}
			if e != nil {
				log.Println(e.Error())
				return
			}
		} else {
			log.Println("服务器不支持STARTTLS")
			return
		}
	}

	// May auth here. (When you not using the MX server ?)
	if config.Authid != "" || config.Authusr != "" {
		if config.Authusr != "" && config.Authcrammd5 != "" {
			log.Println("Auth with CRAMMD5")
			e = c.Auth(CRAMMD5Auth(config.Fuck, config.Authusr, config.Authcrammd5))
		} else {
			log.Println("Auth with Plain")
			e = c.Auth(PlainAuth(config.Fuck, config.Authid, config.Authusr, config.Authpwd))
		}
		if e != nil {
			log.Println(e.Error())
			return
		}
	}

	e = c.Mail(config.From)
	if e != nil {
		log.Println(e.Error())
		return
	}

	e = c.Rcpt(config.To)
	if e != nil {
		log.Println(e.Error())
		return
	}

	d, e := c.Data()
	if e != nil {
		log.Println(e.Error())
		return
	}
	defer Close(d)

	if config.Raw != "" {
		if f, e := os.Open(config.Raw); e != nil {
			log.Println(e.Error())
			return
		} else {
			defer Close(f)
			if _, e = io.Copy(d, f); e != nil {
				log.Println(e.Error())
				return
			}
		}
		return // 提前退出
	}

	// Setup email headers
	headers := make(map[string]string)
	headers["From"] = config.Name + " <" + config.From + ">"
	headers["To"] = config.To
	if func() bool {
		for _, v := range config.Headers {
			if strings.ToLower(v[:9]) == "reply-to:" {
				return false
			}
		}
		return true
	}() {
		headers["Reply-To"] = "<" + config.From + ">"
	}
	if config.Subject != "" && func() bool {
		for _, v := range config.Headers {
			if strings.ToLower(v[:8]) == "subject:" {
				return false
			}
		}
		return true
	}() {
		headers["Subject"] = config.Subject
	}

	var message string
	for k, v := range headers {
		message += k + ": " + v + "\r\n"
	}
	for _, v := range config.Headers {
		message += v + "\r\n"
	}
	message += "\r\n"

	message += config.Body

	_, e = d.Write([]byte(message))
	if e != nil {
		log.Println(e.Error())
		return
	}

	if config.Bodyfile != "" {
		if e != nil {
			log.Println(e.Error())
			return
		}
		if f, e := os.Open(config.Bodyfile); e != nil {
			log.Println(e.Error())
			return
		} else {
			defer Close(f)
			if _, e = io.Copy(d, f); e != nil {
				log.Println(e.Error())
				return
			}
		}
	}
}

func Close(closer io.Closer) {
	if e := closer.Close(); e != nil {
		log.Println(e.Error())
	}
}
