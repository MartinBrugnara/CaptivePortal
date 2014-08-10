package main

import (
	"log"
	"os/exec"
	"regexp"
	"time"
)

const (
	MAC_REGEXP = "([0-9A-Fa-f]{1,2}(:|-)){5}[0-9A-Fa-f]{1,2}"
)

var (
	timers map[int]*time.Timer
)

func IPtoMAC(ip string) string {

	res, e := exec.Command(*arp, "-n", ip).Output()
	if e != nil {
		// not found
		log.Printf("[WW] %s: %s", e.Error(), string(res))
		return ""
	}

	r := regexp.MustCompile(MAC_REGEXP)
	return r.FindString(string(res))
}

func grant(uid int, ip, mac string) {
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

func block(uid int, ip, mac string) {
	timers[uid].Stop()

	delete(timers, uid)

	if res, e := exec.Command(*iptables,
		"-t mangle -D internet 1 -m mac --mac-source", mac, "-s", ip,
		"-j RETURN").Output(); e != nil {

		log.Printf("[EE] %s: %s", e.Error(), string(res))
		return
	}
}
