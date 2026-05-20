package fingerprint

import "strings"

// trimTarget strips trailing slashes from a target URL so that path
// concatenation (base+"/api/config") never produces a double slash when the
// user passes a target with a trailing slash (e.g. http://host:3000/).
// Call once at the top of each Probe() invocation and use the returned base
// for all URL construction; the original target is preserved in Finding.Target.
func trimTarget(t string) string {
	return strings.TrimRight(t, "/")
}
