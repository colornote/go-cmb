package payroll_old

import (
	"encoding/json"
	"github.com/colornote/go-cmb/constants"
	"github.com/colornote/go-cmb/help"
	"github.com/colornote/go-cmb/models"
	"strconv"
	"time"
)

func Refund(
	userId, asePrivateKey, userPrivateKey, taskId string) (*models.GetPayrollPdfResponse, error) {
	reqData := new(models.PayrollPdfFileRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbPayrollOldQueryTransRefund
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Taskid = taskId

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	//  todo
	res := help.CmbSignRequest(string(req), constants.CmbPayrollOldQueryTransRefund, userId, userPrivateKey, asePrivateKey)

	if res == "" {
		return nil, err
	}

	var resp models.GetPayrollPdfResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		print(err)
	}

	return &resp, err

}
