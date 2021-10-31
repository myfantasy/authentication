package sat

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"io"

	at "github.com/myfantasy/authentication"
	"github.com/myfantasy/mft"
	"github.com/myfantasy/storage"
)

const TypeAT string = "simple"

type Request struct {
	Pwd string `json:"pwd"`
}

type User struct {
	Name       string `json:"name"`
	Pwd        string `json:"pwd"`
	PwdIsEnc   bool   `json:"pwd_is_enc"`
	IsDisabled bool   `json:"is_disabled"`
}

func (u *User) Check(secretInfo []byte,
) (ok bool, userName string, err *mft.Error) {
	if u.IsDisabled {
		return false, userName, nil
	}
	if u.Pwd == "" {
		return true, u.Name, nil
	}
	if len(secretInfo) == 0 {
		return false, userName, nil
	}
	var req Request
	er0 := json.Unmarshal(secretInfo, &req)
	if er0 != nil {
		return false, userName, mft.GenerateError(20310110, er0)
	}
	if !u.PwdIsEnc {
		if u.Pwd == req.Pwd {
			return true, u.Name, nil
		}
		return false, userName, nil
	}
	h512 := sha512.New()
	_, er0 = io.WriteString(h512, req.Pwd)
	if er0 != nil {
		return false, userName, mft.GenerateError(20310111, er0)
	}

	pwdEnc := base64.StdEncoding.EncodeToString(h512.Sum(nil))

	if u.Pwd == pwdEnc {
		return true, u.Name, nil
	}
	return false, userName, nil
}

var _ at.AuthenticationChecker = &SimpleAuthenticationChecker{}
var _ storage.Storable = &SimpleAuthenticationChecker{}

//var _ ajt.Api = &SimpleAuthenticationChecker{}

type SimpleAuthenticationChecker struct {
	storage.SaveObjectProto

	Users map[string]User `json:"users,omitempty"`
}

func (spc *SimpleAuthenticationChecker) ToBytes() (data []byte, err *mft.Error) {
	b, er0 := json.Marshal(spc)
	if er0 != nil {
		return nil, mft.GenerateErrorE(10510000, er0)
	}
	return b, nil
}
func (spc *SimpleAuthenticationChecker) FromBytes(data []byte) (err *mft.Error) {
	er0 := json.Unmarshal(data, &spc)
	if er0 != nil {
		return mft.GenerateErrorE(10510000, er0)
	}
	return nil
}

func (spc *SimpleAuthenticationChecker) Type() string {
	return TypeAT
}

func (sac *SimpleAuthenticationChecker) Check(
	ctx context.Context, userNameRequest string, secretInfo []byte,
) (ok bool, userName string, err *mft.Error) {
	if sac == nil {
		return true, userName, nil
	}
	if sac.DataRLock(ctx) {
		return false, userName, mft.GenerateError(20310100)
	}
	defer sac.DataRUnlock()
	if len(sac.Users) == 0 {
		return true, userName, nil
	}

	u, ok := sac.Users[userNameRequest]
	if !ok {
		return false, userName, nil
	}

	return u.Check(secretInfo)
}