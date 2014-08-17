package captive

import (
	"github.com/MartinBrugnara/goforms/forms"
	"html/template"
	"net/http"
	"reflect"
)

// Display login form (handle: GET)
func splash(w http.ResponseWriter, r *http.Request) {
	login(w, r, nil)
}

// Authenticate (handle: POST)
func auth(w http.ResponseWriter, r *http.Request) {
	f := forms.Form{Fields: FFlogin}
	f.Data = r.Form

	// Invalid submission
	if !f.IsValid() {
		// Give the form as it's
		ecntx := reflect.Copy(r.Form)

		// Clean fields with errors
		es := make([]string, len(f.Errors))
		x := 0
		for k, e := range f.Errors {
			delete(ecntx, k)
			es[x] = e
		}

		// collapses error message SD
		ecntx["no_auth_error"] = strings.Join(es, ", ")

		// Delete Password
		delete(ecntx, "password")

		// display login form with errors
		return login(w, r, ecntx)
	}

	// Try to login
	s := do_login(f.CleanedData)
	switch s {
	case nil:
		http.Redirect(w, r, REDIRECT_URL, http.StatusFound)
	case E_AUTH_Deny:
		fallthrough
	case E_AUTH_Expired:
		fallthrough
	case E_AUTH_Blacklist:
		fallthrough
		ecntx := reflect.Copy(r.Form)
		ecntx["no_auth_error"] = s.Error()
		delete(ecntx, "password")
		return login(w, r, ecntx)
	}

}

// Template cache
var tpl_login *template.Template = nil

// Generate and display login page
func login_page(w http.ResponseWriter, r *http.Request, ext_cntx map[string]interface{}) {
	// If the template is not cached, load it.
	if tpl_login == nil {
		if t, e := template.ParseFiles(TEMPLATE + "splash.html"); e != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			log.Fatal(e.Error())
			return
		}
	}

	// Generate base context
	cntx := make(map[string]interface{})
	{
		ip := strings.Split(r.RemoteAddr, ":")[0]
		mac, err := IPtoMAC(ip)
		cntx := map[string]interface{}{
			"ip":            ip,
			"mac":           mac,
			"no_mac":        err != nil,
			"no_auth_error": "",
		}
	}

	// update the context
	for k, v := range ext_cntx {
		cntx[k] = v
	}

	// Render
	t.Execute(w, cntx)
}
