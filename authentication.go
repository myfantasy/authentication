package authentication

import (
	"context"

	"github.com/myfantasy/mft"
)

type AuthenticationChecker interface {
	Type() string
	Check(ctx context.Context, userNameRequest string, secretInfo []byte) (ok bool, userName string, err *mft.Error)
}
