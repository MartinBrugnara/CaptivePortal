package captive

import (
	"github.com/MartinBrugnara/goforms/fields"
	"github.com/MartinBrugnara/goforms/forms"
)

const (
	MAC_STD_REGEXP = "([0-9A-Fa-f]{2}:{5,7})[0-9A-Fa-f]{2}"
	IP_REGEXP      = "([0-9]{1,3}\\.){3}[0-9]{1,3}"

	USER_REGEXP     = "[a-Z0-9\\.]{2,}"
	PASSWORD_REGEXP = "[a-Z0-9]{8}"
)

var (
	FFLogin = forms.FormFields{
		"mac": fields.NewRegexField(fields.Defaults{
			"Required":    true,
			"MatchString": MAC_STD_REGEXP,
		}),
		"ip": fields.NewRegexField(fields.Defaults{
			"Required":    true,
			"MatchString": IP_REGEXP,
		}),
		"username": fields.NewRegexField(fields.Defaults{
			"Required":    true,
			"MatchString": USER_REGEXP,
		}),
		"password": fields.NewRegexField(fields.Defaults{
			"Required":    true,
			"MatchString": PASSWORD_REGEXP,
		}),
	}
)
