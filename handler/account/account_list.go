package account

import (
	"encoding/json"
	"github.com/colornote/go-cmb/constants"
	"github.com/colornote/go-cmb/help"
	"github.com/colornote/go-cmb/models"
	"strconv"
	"time"
)

// MainAccountUsers
// @Description:   获取可经办列表
// @Author ahKevinXy
// @Date 2023-02-13 13:16:21
func MainAccountUsers(userId, asePrivateKey, userPrivateKey, buscod, busmod string) (*models.MainAccountUsersResponse, error) {
	reqData := new(models.MainAccountUsersRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbAccountUserList
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Buscode = buscod
	reqData.Request.Body.Busmod = busmod
	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	//  todo 优化 返回参数
	res := help.CmbSignRequest(string(req), constants.CmbAccountUserList, userId, userPrivateKey, asePrivateKey)

	if res == "" {

		return nil, err
	}

	var resp models.MainAccountUsersResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
