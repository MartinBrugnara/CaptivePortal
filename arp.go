package captive

import (
	"log"
	"net"
	"os/exec"
	"regexp"
	"time"
)

const (
	MAC_REGEXP = "(([0-9A-Fa-f]{1,2}(:|-)){5,7}[0-9A-Fa-f]{1,2}|([0-9A-Fa-f]{1,4}\\.){2,3}[0-9A-Fa-f]{1,4})"

	not_in_cache = "no entry"
)

var (
	E_ARP_NotInCache   error
	E_ARP_ParsingError error
)

func IPtoMAC(ip string) (net.HardwareAddr, error) {
	var output string
	if output, e := exec.Command(*arp, "-n", ip).Output(); e != nil {
		if strings.Containts(output, not_in_cache) {
			return "", E_ARP_NotInCache
		}

		// Arp error
		log.Printf("[WW] %s: %s", e.Error(), string(output))
		return "", e
	}

	r := regexp.MustCompile(MAC_REGEXP)
	if mac := r.FindString(string(res)); len(mac) != 0 {
		return NormalizeMac(mac)
	} else {
		return "", E_ARP_ParsingError
	}
}

// Supports standard and not formats:
// 01:23:45:67:89:ab
// 01:23:45:67:89:ab:cd:ef
// 01-23-45-67-89-ab
// 01-23-45-67-89-ab-cd-ef
// 0123.4567.89ab
// 0123.4567.89ab.cdef
// 0:a:e4:13:f9:1c
// 0-a-e4-13-f9-1c
// 0::e4::f9:1c
// 0--e4--f9-1c
func NormalizeMac(mac string) (net.HardwareAddr, error) {
	if strings.Index(mac, ".") != -1 {
		return net.ParseMac(string)
	} else {
		r := regexp.MustCompile("(:|-)")
		mac_parts := r.Split(mac_a)
		mac_normalized = make([]string, len(mac_parts))

		for x, p := range mac_parts {
			switch len(p) {
			case 0:
				mac_parts[x] = "00"
			case 1:
				mac_parts[x] = fmt.Sprintf("0%s", p)
			case 2:
				mac_parts[x] = p
			}
		}
		return net.ParseMac(strings.Join(mac_normalized, ":"))
	}
}

// Allow an user to navigate
func Grant(uid int, ip, mac string) {
	if res, e := exec.Command(*iptables,
		"-t mangle -I internet 1 -m mac --mac-source", mac, "-s", ip,
		"-j RETURN").Output(); e != nil {

		log.Printf("[EE] %s: %s", e.Error(), string(res))
		return
	}

	var ttl time.Duration // TODO: calculate and set
	timers[uid] = time.AfterFunc(ttl, func() {
		block(uid, ip, mac)
	})
}

// Do not allow (anymore) the user to navigate
func Block(uid int, ip, mac string) {
	timers[uid].Stop()

	delete(timers, uid)

	if res, e := exec.Command(*iptables,
		"-t mangle -D internet 1 -m mac --mac-source", mac, "-s", ip,
		"-j RETURN").Output(); e != nil {

		log.Printf("[EE] %s: %s", e.Error(), string(res))
		return
	}
}
