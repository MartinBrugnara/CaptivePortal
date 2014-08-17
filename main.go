package captive

import (
	"flag"
	"github.com/gorilla/pat"
	"html/template"
	"log"
	"net/http"
	"strings"
)

var (
	arp      *string
	iptables *string
)

func main() {
	addr := flag.String("addr", ":80", "Addr to server")
	arp = flag.String("arp", "/usr/sbin/arp", "arp executable path")
	iptables = flag.String("iptables", "/sbin/iptables", "iptables executable path")

	flag.Parse()

	r := pat.New()

	r.Get("/", splash)
	r.Post("/", authenticate)

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func splash(w http.ResponseWriter, r *http.Request) {
	if t, e := template.ParseFiles("./html/splash.html"); e != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Printf(e.Error())
		return
	} else {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		mac := IPtoMAC(ip)
		cntx := map[string]interface{}{
			"ip":     ip,
			"mac":    mac,
			"in_use": false, // TODO: Get From DB
			"no_mac": len(mac) == 0,
		}
		t.Execute(w, cntx)
	}
}

func authenticate(w http.ResponseWriter, r *http.Request) {
}
