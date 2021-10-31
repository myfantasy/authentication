package authentication

import "github.com/myfantasy/mft"

type Authentication interface {
	Type() string
	Check(userNameRequest string, secretInfo []byte) (ok bool, userName string, err *mft.Error)
}
