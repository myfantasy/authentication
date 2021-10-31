package authentication

import "github.com/myfantasy/mft"

// Errors codes and description
var Errors map[int]string = map[int]string{
	20310000: "authentication.sat.SimpleAuthenticationChecker.ToBytes: fail to marshal",
	20310010: "authentication.sat.SimpleAuthenticationChecker.FromBytes: fail to unmarshal",

	20310100: "authentication.sat.SimpleAuthenticationChecker.Check: DataRLock fail",
	20310110: "authentication.sat.User.Check: fail to unmarshal secret_info",
	20310111: "authentication.sat.User.Check: fail to make hash",
}

func init() {
	mft.AddErrorsCodes(Errors)
}
