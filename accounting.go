package captive

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

const (
	// Manage the possibility to use the same account on more device
	SimulaneousConnection = false
)

var (
	E_AUTH_Deny      = errors.New("Wrong username password combination")
	E_AUTH_Expired   = errors.New("Your account has beeen expired")
	E_AUTH_Blacklist = errors.New("Your account is blacklisted")
)

type loggedUser struct {
	Uid        int
	Username   string
	Expiration time.Time
	Whitelist  bool
	Blacklist  bool
	Mac        string
	Ip         string
}

/* TIPS: Prevent BF, mitigate DOS (if not yet by iptables)
   set up something like
       failed map[int]*time.Timer()
       banned[int]*time.Timer()
       max_errors:5
       duration:1 minute
       ban: 5 minute

   * on auth success: delete(failed, uid)
   * on failure:
       if len(failed[uid]) ==  max_errors
           banned[uid] = new
           delete(failed, uid)
           notify banned untill
       else
           failed[uid].append new
   * timers:
       when fire: remove them self from map
*/

// Account timers (block if account expire)
var timers map[int]*time.Timer

/* TIPS: Allow N connection
   - Replacing this with a map[int][]*time.Timer;
   - if N = +inf
       * do not reset timer at the end of the do_login func
   - if 0 < N < +inf
       * if len(map[uid]) == N:
           map[uid].Dequeue().Reset()
       map[uid].Enqueue(this session)
*/

func do_login(data map[string]interface{}) error {
	var (
		query string
		tx    *sql.Tx
	)

	if tx, e := db.Begin(); e != nil {
		log.Fatal("[EE] Failed to start transaction: %s", e)
	}

	u := loggedUser{
		Username: data["username"].(string),
		Mac:      data["mac"].(string),
		Ip:       data["ip"].(string),
	}

	// Check if can login
	{
		query = "SELECT uid, expiration, expiration < current_time, whitelist, blacklist FROM accounts " +
			"WHERE username=$1 AND password=crypt($2, password)"
		var expired bool
		e := tx.QueryRow(query, data["username"], data["password"]).Scan(
			&u.Uid, &u.Expiration, &expired, &u.Whitelist, &u.Blacklist)

		if e == sql.ErrNoRows {
			log.Printf("[AD PWD] %s %s > %s", u.Ip, u.Mac, u.Username)
			tx.Rollback()
			return E_AUTH_Deny
		} else if e != nil {
			log.Printf("[EE] DB: %s", e)
			tx.Rollback()
			return e
		}
		if expired {
			log.Printf("[AD EXP] %s %s > %s", u.Ip, u.Mac, u.Username)
			tx.Rollback()
			return E_AUTH_Expired
		}
		if u.Blacklist {
			log.Printf("[AD BL] %s %s > %s", u.Ip, u.Mac, u.Username)
			tx.Rollback()
			return E_AUTH_Blacklist
		}
	}

	// Insert current session
	query = "INSERT INTO session (uid, ip, mac) VALUES ($1, $2, $3)"
	{
		if _, e := tx.Exec(query, u.Uid, u.Ip, u.Mac); e != nil {
			log.Printf("[EE] DB: %s", e)
			tx.Rollback()
			return e
		}

		// Allow the user to navigate
		Grant(u.Uid, u.Ip, u.Mac)

		// Insert the timer for the new session
		if !u.Whitelist {
			ttl := u.Expiration.Sub(time.Now())
			timers[u.Uid] = time.AfterFunc(ttl, func() {
				// TODO: check if is better to copy the values (gc?)
				Block(u.Uid, u.Ip, u.Mac)
			})

			// Close the old session (if it exists)
			if !SimulaneousConnection {
				if old, exists := timers[u.Uid]; exists {
					// Not sure what would happen using time.Nanosecond
					old.Reset(time.Second)
				}
			}
		}
	}

	return tx.Commit()
}
