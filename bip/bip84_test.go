// Adapted from github.com/KaiWitt/go-bip84
// Fixed some dependency issues
package bip

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

var (
	seed, _  = hex.DecodeString("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
	mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

func TestConvertMnemonicToSeed(t *testing.T) {
	type args struct {
		mnemonic string
		password string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Convert mnemonic to seed",
			args: args{
				mnemonic: mnemonic,
				password: "",
			},
			want:    seed,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertMnemonicToSeed(tt.args.mnemonic, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertMnemonicToSeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertMnemonicToSeed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAddressFromMnemonic(t *testing.T) {
	type args struct {
		mnemonic  string
		password  string
		account   uint32
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive first receive address",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: true,
				index:     0,
			},
			want:    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
			wantErr: false,
		},
		{
			name: "Derive first change address",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: false,
				index:     0,
			},
			want:    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
			wantErr: false,
		},
		{
			name: "Derive second receive address",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: true,
				index:     1,
			},
			want:    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
			wantErr: false,
		},
		{
			name: "Derive second change address",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: false,
				index:     1,
			},
			want:    "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAddressFromMnemonic(tt.args.mnemonic, tt.args.password, tt.args.account, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAddressFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.EncodeAddress()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetAddressFromMnemonic() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetAddressFromSeed(t *testing.T) {
	type args struct {
		seed      []byte
		account   uint32
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive first receive address",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: true,
				index:     0,
			},
			want:    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
			wantErr: false,
		},
		{
			name: "Derive first change address",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: false,
				index:     0,
			},
			want:    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
			wantErr: false,
		},
		{
			name: "Derive second receive address",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: true,
				index:     1,
			},
			want:    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
			wantErr: false,
		},
		{
			name: "Derive second change address",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: false,
				index:     1,
			},
			want:    "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAddressFromSeed(tt.args.seed, tt.args.account, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAddressFromSeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.EncodeAddress()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetAddressFromSeed() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetAddressFromZPubKey(t *testing.T) {
	zpub, err := hdkeychain.NewKeyFromString("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
	if err != nil {
		t.Error("Unable to read extended public key:", err)
	}
	type args struct {
		zpub      *hdkeychain.ExtendedKey
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive first receive address",
			args: args{
				zpub:      zpub,
				isReceive: true,
				index:     0,
			},
			want:    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
			wantErr: false,
		},
		{
			name: "Derive first change address",
			args: args{
				zpub:      zpub,
				isReceive: false,
				index:     0,
			},
			want:    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
			wantErr: false,
		},
		{
			name: "Derive second receive address",
			args: args{
				zpub:      zpub,
				isReceive: true,
				index:     1,
			},
			want:    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
			wantErr: false,
		},
		{
			name: "Derive second change address",
			args: args{
				zpub:      zpub,
				isReceive: false,
				index:     1,
			},
			want:    "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAddressFromZPubKey(tt.args.zpub, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAddressFromZPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.EncodeAddress()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetAddressFromZPubKey() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetAddressFromZPubKeyString(t *testing.T) {
	type args struct {
		zpub      string
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive first receive address",
			args: args{
				zpub:      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
				isReceive: true,
				index:     0,
			},
			want:    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
			wantErr: false,
		},
		{
			name: "Derive first change address",
			args: args{
				zpub:      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
				isReceive: false,
				index:     0,
			},
			want:    "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
			wantErr: false,
		},
		{
			name: "Derive second receive address",
			args: args{
				zpub:      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
				isReceive: true,
				index:     1,
			},
			want:    "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
			wantErr: false,
		},
		{
			name: "Derive second change address",
			args: args{
				zpub:      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
				isReceive: false,
				index:     1,
			},
			want:    "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAddressFromZPubKeyString(tt.args.zpub, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAddressFromZPubKeyString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.EncodeAddress()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetAddressFromZPubKeyString() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetWifFromMnemonic(t *testing.T) {
	type args struct {
		mnemonic  string
		password  string
		account   uint32
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Derive first receive private key",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: true,
				index:     0,
			},
			want:    "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
			wantErr: false,
		},
		{name: "Derive first change private key",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: false,
				index:     0,
			},
			want:    "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
			wantErr: false,
		},
		{name: "Derive second receive private key",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: true,
				index:     1,
			},
			want:    "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
			wantErr: false,
		},
		{name: "Derive second change private key",
			args: args{
				mnemonic:  mnemonic,
				password:  "",
				account:   0,
				isReceive: false,
				index:     1,
			},
			want:    "KyDKM6os4SNpyCN79CGaZF91vVtzmnragXN7A3qAxVvFDws9jBqh",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWifFromMnemonic(tt.args.mnemonic, tt.args.password, tt.args.account, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWifFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetWifFromMnemonic() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetWifFromSeed(t *testing.T) {
	type args struct {
		seed      []byte
		account   uint32
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Derive first receive private key",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: true,
				index:     0,
			},
			want:    "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
			wantErr: false,
		},
		{name: "Derive first change private key",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: false,
				index:     0,
			},
			want:    "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
			wantErr: false,
		},
		{name: "Derive second receive private key",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: true,
				index:     1,
			},
			want:    "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
			wantErr: false,
		},
		{name: "Derive second change private key",
			args: args{
				seed:      seed,
				account:   0,
				isReceive: false,
				index:     1,
			},
			want:    "KyDKM6os4SNpyCN79CGaZF91vVtzmnragXN7A3qAxVvFDws9jBqh",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWifFromSeed(tt.args.seed, tt.args.account, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWifFromSeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetWifFromSeed() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetWifFromZPrivKey(t *testing.T) {
	zpriv, err := hdkeychain.NewKeyFromString("zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE")
	if err != nil {
		t.Error("Unable to read extended private key:", err)
	}
	type args struct {
		zpriv     *hdkeychain.ExtendedKey
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Derive first receive private key",
			args: args{
				zpriv:     zpriv,
				isReceive: true,
				index:     0,
			},
			want:    "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
			wantErr: false,
		},
		{name: "Derive first change private key",
			args: args{
				zpriv:     zpriv,
				isReceive: false,
				index:     0,
			},
			want:    "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
			wantErr: false,
		},
		{name: "Derive second receive private key",
			args: args{
				zpriv:     zpriv,
				isReceive: true,
				index:     1,
			},
			want:    "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
			wantErr: false,
		},
		{name: "Derive second change private key",
			args: args{
				zpriv:     zpriv,
				isReceive: false,
				index:     1,
			},
			want:    "KyDKM6os4SNpyCN79CGaZF91vVtzmnragXN7A3qAxVvFDws9jBqh",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWifFromZPrivKey(tt.args.zpriv, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetWifFromZPrivKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetWifFromZPrivKey() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetWifFromZPrivKeyString(t *testing.T) {
	type args struct {
		zpriv     string
		isReceive bool
		index     uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Derive first receive private key",
			args: args{
				zpriv:     "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
				isReceive: true,
				index:     0,
			},
			want:    "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
			wantErr: false,
		},
		{name: "Derive first change private key",
			args: args{
				zpriv:     "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
				isReceive: false,
				index:     0,
			},
			want:    "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
			wantErr: false,
		},
		{name: "Derive second receive private key",
			args: args{
				zpriv:     "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
				isReceive: true,
				index:     1,
			},
			want:    "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
			wantErr: false,
		},
		{name: "Derive second change private key",
			args: args{
				zpriv:     "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
				isReceive: false,
				index:     1,
			},
			want:    "KyDKM6os4SNpyCN79CGaZF91vVtzmnragXN7A3qAxVvFDws9jBqh",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetWifFromZPrivKeyString(tt.args.zpriv, tt.args.isReceive, tt.args.index)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrivKeyFromZPrivKeyString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetPrivKeyFromZPrivKeyString() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetZPrivKeyFromMnemonic(t *testing.T) {
	type args struct {
		mnemonic string
		password string
		account  uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive extended private Key of account 0",
			args: args{
				mnemonic: mnemonic,
				password: "",
				account:  0,
			},
			want:    "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
			wantErr: false,
		},
		{
			name: "Derive extended private Key of account 1",
			args: args{
				mnemonic: mnemonic,
				password: "",
				account:  1,
			},
			want:    "zprvAdG4iTXWBoAS2cCGuaGevCvH54GCunrvLJb2hoWCSuE3D9LS42XVg3c6sPm64w6VMq3w18vJf8nF3cBA2kUMkyWHsq6enWVXivzw42UrVHG",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetZPrivKeyFromMnemonic(tt.args.mnemonic, tt.args.password, tt.args.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetZPrivKeyFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetZPrivKeyFromMnemonic() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetZPrivKeyFromSeed(t *testing.T) {
	type args struct {
		seed    []byte
		account uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive extended private Key of account 0",
			args: args{
				seed:    seed,
				account: 0,
			},
			want:    "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
			wantErr: false,
		},
		{
			name: "Derive extended private Key of account 1",
			args: args{
				seed:    seed,
				account: 1,
			},
			want:    "zprvAdG4iTXWBoAS2cCGuaGevCvH54GCunrvLJb2hoWCSuE3D9LS42XVg3c6sPm64w6VMq3w18vJf8nF3cBA2kUMkyWHsq6enWVXivzw42UrVHG",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetZPrivKeyFromSeed(tt.args.seed, tt.args.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetZPrivKeyFromSeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetZPrivKeyFromSeed() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetZPubKeyFromSeed(t *testing.T) {
	type args struct {
		seed    []byte
		account uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive extended public key of account 0",
			args: args{
				seed:    seed,
				account: 0,
			},
			want:    "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
			wantErr: false,
		},
		{
			name: "Derive extended public key of account 1",
			args: args{
				seed:    seed,
				account: 1,
			},
			want:    "zpub6rFR7y4Q2AijF6Gk1bofHLs1d66hKFamhXWdWBup1Em25wfabZqkDqvaieV63fDQFaYmaatCG7jVNUpUiM2hAMo6SAVHcrUpSnHDpNzucB7",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetZPubKeyFromSeed(tt.args.seed, tt.args.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetZPubKeyFromSeed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetZPubKeyFromSeed() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGetZPubKeyFromMnemonic(t *testing.T) {
	type args struct {
		mnemonic string
		password string
		account  uint32
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Derive extended public key of account 0",
			args: args{
				mnemonic: mnemonic,
				password: "",
				account:  0,
			},
			want:    "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
			wantErr: false,
		},
		{
			name: "Derive extended public key of account 1",
			args: args{
				mnemonic: mnemonic,
				password: "",
				account:  1,
			},
			want:    "zpub6rFR7y4Q2AijF6Gk1bofHLs1d66hKFamhXWdWBup1Em25wfabZqkDqvaieV63fDQFaYmaatCG7jVNUpUiM2hAMo6SAVHcrUpSnHDpNzucB7",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetZPubKeyFromMnemonic(tt.args.mnemonic, tt.args.password, tt.args.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetZPubKeyFromMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			have := got.String()
			if !reflect.DeepEqual(have, tt.want) {
				t.Errorf("GetZPubKeyFromMnemonic() = %v, want %v", have, tt.want)
			}
		})
	}
}

func TestGenerate12WordMnemonic(t *testing.T) {
	tests := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{
			name:    "Generate 12 words",
			want:    12,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Generate12WordMnemonic()
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate12WordMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(strings.Split(got, " ")) != tt.want {
				t.Errorf("Generate12WordMnemonic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerate24WordMnemonic(t *testing.T) {
	tests := []struct {
		name    string
		want    int
		wantErr bool
	}{
		{
			name:    "Generate 24 words",
			want:    24,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Generate24WordMnemonic()
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate24WordMnemonic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(strings.Split(got, " ")) != tt.want {
				t.Errorf("Generate24WordMnemonic() = %v, want %v", got, tt.want)
			}
		})
	}
}
