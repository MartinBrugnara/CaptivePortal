package captive

import (
	"flag"
	"github.com/gorilla/pat"
	"log"
	"net/http"
)

var (
	ARP          string
	IPTABLES     string
	TEMPLATE     string
	REDIRECT_URL string
)

func main() {
	captive := flag.String("addr", ":80", "captive portal addr")

	flag.StringVar(ARP, "arp", "/usr/sbin/arp", "arp executable path")
	flag.StringVar(IPTABLES, "iptables", "/sbin/iptables", "iptables executable path")
	flag.StringVar(TEMPLATE, "template", "./html/", "html template directory")
	flag.StringVar(REDIRECT_URL, "redir", "http://www.google.com", "next page after successfully login")

	flag.Parse()

	r := pat.New()

	r.Get("/", splash)
	r.Post("/", auth)

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(*captive, nil))
}
