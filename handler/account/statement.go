package account

import (
	"encoding/json"
	"github.com/ahKevinXy/go-cmb/constants"
	"github.com/ahKevinXy/go-cmb/help"
	"github.com/ahKevinXy/go-cmb/models"
	"strconv"
	"time"
)

// 回单

// AsyncStatement
//  @Description:   异步获取回单
//  @param userId
//  @param asePrivateKey
//  @param userPrivateKey
//  @param eacnbr
//  @param begdat
//  @param enddat
//  @param begamt
//  @param endamt
//  @param category
//  @return *models.QueryAccountCallbackAsyncResponse
//  @return error
//  @Author  ahKevinXy
//  @Date2023-04-10 15:05:15
func AsyncStatement(userId, asePrivateKey, userPrivateKey,
	eacnbr,
	begdat,
	enddat,
	begamt,
	endamt string) (*models.QueryAccountCallbackAsyncResponse, error) {
	reqData := new(models.QueryAccountCallbackAsyncRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbAccountQueryAsyncStatement
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Primod = "PDF"
	reqData.Request.Body.Eacnbr = eacnbr
	reqData.Request.Body.Begdat = begdat
	reqData.Request.Body.Enddat = enddat
	reqData.Request.Body.Rrcflg = "1"
	reqData.Request.Body.Begamt = begamt
	reqData.Request.Body.Endamt = endamt

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, nil
	}

	//  todo
	res := help.CmbSignRequest(string(req), constants.CmbAccountQueryAsyncStatement, userId, userPrivateKey, asePrivateKey)

	if res == "" {
		return nil, nil
	}

	var resp models.QueryAccountCallbackAsyncResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		print(err)
	}

	return &resp, nil
}

// SingleStatementQuery
//  @Description:  单个回单请求
//  @param userId
//  @param asePrivateKey
//  @param userPrivateKey
//  @param eacnbr
//  @param quedat
//  @param trsseq
//  @param primod
//  @return *models.SingleCallBackPdfResponse
//  @return error
//  @Author  ahKevinXy
//  @Date2023-04-10 15:09:21
func SingleStatementQuery(userId, asePrivateKey, userPrivateKey, eacnbr, quedat, trsseq, primod string) (*models.SingleCallBackPdfResponse, error) {
	reqData := new(models.SingleCallBackPdfRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbAccountQuerySingleStatement
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"

	reqData.Request.Body.Eacnbr = eacnbr
	reqData.Request.Body.Quedat = quedat
	reqData.Request.Body.Trsseq = trsseq
	reqData.Request.Body.Primod = primod

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, nil
	}

	//  todo
	res := help.CmbSignRequest(string(req), constants.CmbAccountQuerySingleStatement, userId, userPrivateKey, asePrivateKey)

	if res == "" {
		return nil, nil
	}

	var resp models.SingleCallBackPdfResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		print(err)
	}

	return &resp, nil
}

// GetStatementPdf
//  @Description:   获取回单文件
//  @param userId
//  @param asePrivateKey
//  @param userPrivateKey
//  @param taskid
//  @param qwenab
//  @param category
//  @return *models.QueryAccountCallbackDownloadPdfResponse
//  @return error
//  @Author  ahKevinXy
//  @Date2023-04-10 15:09:59
func GetStatementPdf(userId, asePrivateKey, userPrivateKey, taskid, qwenab, category string) (*models.QueryAccountCallbackDownloadPdfResponse, error) {
	reqData := new(models.QueryAccountCallbackDownloadPdfRequest)
	reqData.Request.Head.Reqid = time.Now().Format("20060102150405000") + strconv.Itoa(time.Now().Nanosecond())
	reqData.Request.Head.Funcode = constants.CmbAccountQueryAsyncDownloadStatement
	reqData.Request.Head.Userid = userId
	reqData.Signature.Sigtim = time.Now().Format("20060102150405")
	reqData.Signature.Sigdat = "__signature_sigdat__"
	reqData.Request.Body.Taskid = taskid
	reqData.Request.Body.Qwenab = qwenab

	req, err := json.Marshal(reqData)
	if err != nil {
		return nil, nil
	}

	//  todo
	res := help.CmbSignRequest(string(req), constants.CmbAccountQueryAsyncDownloadStatement, userId, userPrivateKey, asePrivateKey)

	if res == "" {
		return nil, nil
	}

	var resp models.QueryAccountCallbackDownloadPdfResponse

	if err := json.Unmarshal([]byte(res), &resp); err != nil {
		print(err)
	}

	return &resp, nil
}
