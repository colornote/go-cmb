package help

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/colornote/go-cmb/config"
	"github.com/colornote/go-cmb/models"
	"github.com/tjfoc/gmsm/sm4"
)

// CmbSignRequest
//
//	@Description:  招商银行 统一请求
//	@param reqStr 请求参数
//	@param funCode 请求代码
//	@param uid   用户ID
//	@param userKey 用户秘钥
//	@param AESKey 用户对称秘钥
//	@return string 结果返回
//	@Author  ahKevinXy
//	@Date2023-04-10 13:41:37
func CmbSignRequest(reqStr string, funCode, uid, userKey, AESKey string) string {

	return SignatureDataStandarSM(reqStr, funCode, uid, userKey, AESKey)

}

// SignatureDataStandarSM 标准直接，非saas， 不需要INSPLAT参数，不需要paltsigdat参数 todo: 验签
func SignatureDataStandarSM(
	reqStr, funCode, uid, userKey, AESKey string) string {

	reqStr = GetJson(reqStr)
	var reqV1 models.ReqV1

	if err := json.Unmarshal([]byte(reqStr), &reqV1); err != nil {
		fmt.Println(err)
		return ""
	}

	reqStr = strings.ReplaceAll(reqStr, "\n", "")
	reqStr = strings.ReplaceAll(reqStr, "\r", "")
	reqStr = strings.ReplaceAll(reqStr, " ", "")

	//用户签名

	priv, err := FormatPri(userKey)
	if err != nil {
		panic("decode private key fail")
	}

	reqSign, err := SM3WithSM2Sign(priv, reqStr, getID_IV())

	if err != nil {
		fmt.Println(err)
		return ""
	}

	signatureV1 := models.SignatureV1{Sigtim: reqV1.SignatureV1.Sigtim, Sigdat: reqSign}
	reqV1.SignatureV1 = signatureV1
	reqV1Json, err := json.Marshal(reqV1)

	if err != nil {
		fmt.Println(err)
		return ""
	}

	userId := uid + "000000"
	reqNewAccountAes, err := Sm4Encrypt([]byte(AESKey), []byte(userId), reqV1Json)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	u := url.Values{}

	u.Set("ALG", "SM")
	u.Set("DATA", base64.StdEncoding.EncodeToString(reqNewAccountAes))
	u.Set("UID", uid)
	u.Set("FUNCODE", funCode)

	u.Encode()

	resp, err := http.PostForm(config.Settings.CmbPay.CmbUrl, u)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)

	var dataStr string
	if !strings.Contains(string(respBody), "ErrMsg") {
		//dataByte, err := sm4.Sm4Cbc([]byte(AESKey), respBody, false)
		//if err != nil {
		//	fmt.Println(err)
		//	return ""
		//}
		//dataStr = string(dataByte)

		respBody64, err := base64.StdEncoding.DecodeString(string(respBody))
		dataByte, err := sm4Decrypt([]byte(AESKey), []byte(userId), respBody64)
		if err != nil {

			fmt.Println(string(reqV1Json), "++++错误信息++++", string(respBody))
			return ""
		}
		dataStr = string(dataByte)
	} else {
		dataStr = string(respBody)
	}

	return dataStr
}

func SignatureDataSM(
	reqStr, funCode, uid, userKey, AESKey string) string {

	reqStr = GetJson(reqStr)
	var reqV1 models.ReqV1

	if err := json.Unmarshal([]byte(reqStr), &reqV1); err != nil {
		fmt.Println(err)
		return ""
	}

	reqStr = strings.ReplaceAll(reqStr, "\n", "")
	reqStr = strings.ReplaceAll(reqStr, "\r", "")
	reqStr = strings.ReplaceAll(reqStr, " ", "")

	//用户签名
	reqSign, err := SignSM2(reqStr, userKey, uid)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	//平台方签名
	reqSignSaas, err := SignSM2(reqSign, config.Settings.CmbPay.CmbSaasPrivateKey, uid)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	signatureV1 := models.SignatureV1{Sigtim: reqV1.SignatureV1.Sigtim, Sigdat: reqSign, Paltsigdat: reqSignSaas}
	reqV1.SignatureV1 = signatureV1
	reqV1Json, err := json.Marshal(reqV1)

	if err != nil {
		fmt.Println(err)
		return ""
	}

	userId := uid + "000000"
	reqNewAccountAes, err := Sm4Encrypt([]byte(AESKey), []byte(userId), reqV1Json)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	u := url.Values{}

	u.Set("ALG", "SM")
	u.Set("DATA", base64.StdEncoding.EncodeToString(reqNewAccountAes))
	u.Set("INSPLAT", config.Settings.CmbPay.CmbSaasName)
	u.Set("UID", uid)
	u.Set("FUNCODE", funCode)

	u.Encode()

	resp, err := http.PostForm(config.Settings.CmbPay.CmbUrl, u)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)

	var dataStr string
	if !strings.Contains(string(respBody), "ErrMsg") {
		//dataByte, err := sm4.Sm4Cbc([]byte(AESKey), respBody, false)
		//if err != nil {
		//	fmt.Println(err)
		//	return ""
		//}
		//dataStr = string(dataByte)

		respBody64, err := base64.StdEncoding.DecodeString(string(respBody))
		dataByte, err := sm4Decrypt([]byte(AESKey), []byte(userId), respBody64)
		if err != nil {

			fmt.Println(string(reqV1Json), "++++错误信息++++", string(respBody))
			return ""
		}
		dataStr = string(dataByte)
	} else {
		dataStr = string(respBody)
	}

	return dataStr
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
