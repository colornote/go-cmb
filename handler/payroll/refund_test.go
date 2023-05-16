package payroll

import (
	"github.com/colornote/go-cmb/models"
	"reflect"
	"testing"
)

func TestQueryRefundList(t *testing.T) {
	type args struct {
		userId         string
		asePrivateKey  string
		userPrivateKey string
		accNbr         string
		trstyp         string
		bgndat         string
		enddat         string
		cntkey         string
		reqnbr         string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.QueryBatchTransListResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QueryRefundList(tt.args.userId, tt.args.asePrivateKey, tt.args.userPrivateKey, tt.args.accNbr, tt.args.trstyp, tt.args.bgndat, tt.args.enddat, tt.args.cntkey, tt.args.reqnbr)
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryRefundList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QueryRefundList() got = %v, want %v", got, tt.want)
			}
		})
	}
}
