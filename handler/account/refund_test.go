package account

import (
	"github.com/colornote/go-cmb/models"
	"reflect"
	"testing"
)

func TestQueryAccountPaymentRefund(t *testing.T) {
	type args struct {
		userId         string
		asePrivateKey  string
		userPrivateKey string
		bbkNbr         string
		bgnDat         string
		endDat         string
		reqNbr         string
		ctnKey         string
		rsv50z         string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.QueryAccountPaymentRefundResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QueryAccountPaymentRefund(tt.args.userId, tt.args.asePrivateKey, tt.args.userPrivateKey, tt.args.bbkNbr, tt.args.bgnDat, tt.args.endDat, tt.args.reqNbr, tt.args.ctnKey, tt.args.rsv50z)
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryAccountPaymentRefund() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QueryAccountPaymentRefund() got = %v, want %v", got, tt.want)
			}
		})
	}
}
