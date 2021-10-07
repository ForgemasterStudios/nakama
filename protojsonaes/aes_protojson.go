package protojsonaes

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type MarshalOptions struct {
	MarshalOptions   *protojson.MarshalOptions
	UseAESEncryption bool
	AESEncryptionKey []byte
}

type UnmarshalOptions struct {
	UnmarshalOptions *protojson.UnmarshalOptions
	UseAESEncryption bool
	AESEncryptionKey []byte
}

func (o MarshalOptions) Marshal(m proto.Message) ([]byte, error) {
	b, err := o.MarshalOptions.Marshal(m)
	if err != nil {
		return b, err
	}
	if o.UseAESEncryption {
		return Encrypt(o.AESEncryptionKey, b)
	}
	return b, nil
}

func (o UnmarshalOptions) Unmarshal(b []byte, m proto.Message) error {
	if o.UseAESEncryption {
		d, err := Decrypt(o.AESEncryptionKey, b)
		if err != nil {
			return err
		}
		b = d
	}
	return o.UnmarshalOptions.Unmarshal(b, m)
}
