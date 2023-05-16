package account

import (
	"encoding/json"
	"github.com/colornote/go-cmb/constants"
	"github.com/colornote/go-cmb/help"
	"github.com/colornote/go-cmb/models"
	"strconv"
	"time"
)

// PayMods
//
//	@Description:  获取支付模式
//	@param userId
//	@param asePrivateKey
//	@param userPrivateKey
//	@param buscode
//	@Author  ahKevinXy
//	@Date2023-04-06 19:54:15
func PayMods(userId, asePrivateKey, userPrivateKey, busCode string) (*models.QueryAccountTransCodeResponse, error) {

	reqData := new(models.QueryAccountTransCodeRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbAccountCanPayMod
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Buscod = busCode

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	res := help.CmbSignRequest(string(req), constants.CmbAccountCanPayMod, userId, userPrivateKey, asePrivateKey)

	//todo
	if res == "" {

		return nil, err
	}

	var resp models.QueryAccountTransCodeResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		return nil, err
	}
	//fmt.Println(res)
	return &resp, nil
}
