package account

import (
	"github.com/colornote/go-cmb/models"
	"reflect"
	"testing"
)

func TestPayMods(t *testing.T) {
	type args struct {
		userId         string
		asePrivateKey  string
		userPrivateKey string
		busCode        string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.QueryAccountTransCodeResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PayMods(tt.args.userId, tt.args.asePrivateKey, tt.args.userPrivateKey, tt.args.busCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("PayMods() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PayMods() got = %v, want %v", got, tt.want)
			}
		})
	}
}
