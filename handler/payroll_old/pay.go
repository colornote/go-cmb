package payroll_old

import (
	"encoding/json"
	"github.com/colornote/go-cmb/constants"
	"github.com/colornote/go-cmb/help"
	"github.com/colornote/go-cmb/models"
	"strconv"
	"time"
)

// CreditHandleOtherBySup
//
//	@Description:  超网代发
//	@param userId
//	@param asePrivateKey
//	@param userPrivateKey
//	@param busmod 交易模式
//	@param total
//	@param detail
//	@return *models.PayrollOldCreditOtherBySupResponse
//	@return error
//	@Author  ahKevinXy
//	@Date  2023-04-18 09:48:49
func CreditHandleOtherBySup(userId, asePrivateKey, userPrivateKey, busmod string, total []*models.Ntagcsaix1, detail []*models.Ntagcsaix2) (*models.PayrollOldCreditOtherBySupResponse, error) {

	reqData := new(models.PayrollOldCreditOtherBySupRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbPayrollOldSupPay
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Ntbusmody = append(reqData.Request.Body.Ntbusmody, &models.Ntbusmody{
		Busmod: busmod,
	})
	// 代发汇总
	reqData.Request.Body.Ntagcsaix1 = append(reqData.Request.Body.Ntagcsaix1, total...)

	// 代发明细
	reqData.Request.Body.Ntagcsaix2 = append(reqData.Request.Body.Ntagcsaix2, detail...)

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	//  todo
	res := help.CmbSignRequest(string(req), constants.CmbPayrollOldSupPay, userId, userPrivateKey, asePrivateKey)

	if res == "" {
		return nil, err
	}

	var resp models.PayrollOldCreditOtherBySupResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		print(err)
	}

	return &resp, err

}
