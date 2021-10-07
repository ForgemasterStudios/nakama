package protojsonaes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	grpcgw "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/protobuf/proto"
)

type JSONPbAES struct {
	MarshalOptions
	UnmarshalOptions
	UseAESEncryption bool
	AESEncryptionKey []byte
}

func (j *JSONPbAES) ContentType(_ interface{}) string {
	if j.UseAESEncryption {
		return "application/octet-stream"
	} else {
		return "application/json"
	}
}

// Marshal marshals "v" into JSON.
func (j *JSONPbAES) Marshal(v interface{}) ([]byte, error) {
	b, err := j.marshal(v)
	if err != nil {
		return []byte{}, err
	}
	if j.UseAESEncryption {
		return Encrypt(j.AESEncryptionKey, b)
	}
	return b, nil
}

func (j *JSONPbAES) marshal(v interface{}) ([]byte, error) {
	if _, ok := v.(proto.Message); !ok {
		return j.marshalNonProtoField(v)
	}

	var buf bytes.Buffer
	if err := j.marshalTo(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (j *JSONPbAES) marshalTo(w io.Writer, v interface{}) error {
	p, ok := v.(proto.Message)
	if !ok {
		buf, err := j.marshalNonProtoField(v)
		if err != nil {
			return err
		}
		_, err = w.Write(buf)
		return err
	}
	b, err := j.MarshalOptions.Marshal(p)
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	return err
}

var (
	// protoMessageType is stored to prevent constant lookup of the same type at runtime.
	protoMessageType = reflect.TypeOf((*proto.Message)(nil)).Elem()
)

// marshalNonProto marshals a non-message field of a protobuf message.
// This function does not correctly marshal arbitrary data structures into JSON,
// it is only capable of marshaling non-message field values of protobuf,
// i.e. primitive types, enums; pointers to primitives or enums; maps from
// integer/string types to primitives/enums/pointers to messages.
func (j *JSONPbAES) marshalNonProtoField(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return []byte("null"), nil
		}
		rv = rv.Elem()
	}

	if rv.Kind() == reflect.Slice {
		if rv.IsNil() {
			if j.MarshalOptions.MarshalOptions.EmitUnpopulated {
				return []byte("[]"), nil
			}
			return []byte("null"), nil
		}

		if rv.Type().Elem().Implements(protoMessageType) {
			var buf bytes.Buffer
			err := buf.WriteByte('[')
			if err != nil {
				return nil, err
			}
			for i := 0; i < rv.Len(); i++ {
				if i != 0 {
					err = buf.WriteByte(',')
					if err != nil {
						return nil, err
					}
				}
				if err = j.marshalTo(&buf, rv.Index(i).Interface().(proto.Message)); err != nil {
					return nil, err
				}
			}
			err = buf.WriteByte(']')
			if err != nil {
				return nil, err
			}

			return buf.Bytes(), nil
		}
	}

	if rv.Kind() == reflect.Map {
		m := make(map[string]*json.RawMessage)
		for _, k := range rv.MapKeys() {
			buf, err := j.marshal(rv.MapIndex(k).Interface())
			if err != nil {
				return nil, err
			}
			m[fmt.Sprintf("%v", k.Interface())] = (*json.RawMessage)(&buf)
		}
		if j.MarshalOptions.MarshalOptions.Indent != "" {
			return json.MarshalIndent(m, "", j.MarshalOptions.MarshalOptions.Indent)
		}
		return json.Marshal(m)
	}
	if enum, ok := rv.Interface().(protoEnum); ok && !j.MarshalOptions.MarshalOptions.UseEnumNumbers {
		return json.Marshal(enum.String())
	}
	return json.Marshal(rv.Interface())
}

// NewEncoder returns an Encoder which writes JSON stream into "w".
func (j *JSONPbAES) NewEncoder(w io.Writer) grpcgw.Encoder {
	return grpcgw.EncoderFunc(func(v interface{}) error {
		buffer := new(bytes.Buffer)
		if err := j.marshalTo(buffer, v); err != nil {
			return err
		}
		// mimic json.Encoder by adding a newline (makes output
		// easier to read when it contains multiple encoded items)
		_, err := buffer.Write(j.Delimiter())
		if err != nil {
			return err
		}

		if j.UseAESEncryption {
			b := buffer.Bytes()
			d, err := Encrypt(j.AESEncryptionKey, b)
			if err != nil {
				return err
			}
			_, err = w.Write(d)
			return err
		} else {
			// Save the buffer to writer without modification
			_, err = w.Write(buffer.Bytes())
			return err
		}
	})
}

// Unmarshal unmarshals JSON "data" into "v"
func (j *JSONPbAES) Unmarshal(data []byte, v interface{}) error {
	if j.UseAESEncryption {
		b, err := Decrypt(j.AESEncryptionKey, data)
		if err != nil {
			return err
		}
		data = b
	}
	return unmarshalJSONPb(data, j.UnmarshalOptions, v)
}

// DecoderWrapper is a wrapper around a *json.Decoder that adds
// support for protos to the Decode method.
type DecoderWrapper struct {
	io.Reader
	*JSONPbAES
}

// NewDecoder returns a Decoder which reads JSON stream from "r".
func (j *JSONPbAES) NewDecoder(r io.Reader) grpcgw.Decoder {
	return DecoderWrapper{
		Reader:    r,
		JSONPbAES: j,
	}
}

// Decode wraps the embedded decoder's Decode method to support
// protos using a jsonpb.Unmarshaler.
func (d DecoderWrapper) Decode(v interface{}) error {
	var reader io.Reader
	if d.UseAESEncryption {
		buffer := new(bytes.Buffer)
		_, err := io.Copy(buffer, d.Reader)
		if err != nil {
			return err
		}
		// Decode recevied bytes from b64
		b, err := Base64Decode(buffer.Bytes())
		if err != nil {
			return err
		}
		de, err := Decrypt(d.AESEncryptionKey, b)
		if err != nil {
			return err
		}
		buffer.Reset()
		buffer.Write(de)
		reader = buffer
	} else {
		reader = d.Reader
	}
	j := json.NewDecoder(reader)
	return decodeJSONPb(j, d.UnmarshalOptions, v)
}

func Base64Decode(message []byte) (b []byte, err error) {
	var l int
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, err = base64.StdEncoding.Decode(b, message)
	if err != nil {
		return
	}
	return b[:l], nil
}

func unmarshalJSONPb(data []byte, unmarshaler UnmarshalOptions, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(data))
	return decodeJSONPb(d, unmarshaler, v)
}

func decodeJSONPb(d *json.Decoder, unmarshaler UnmarshalOptions, v interface{}) error {
	p, ok := v.(proto.Message)
	if !ok {
		return decodeNonProtoField(d, unmarshaler, v)
	}

	// Decode into bytes for marshalling
	var b json.RawMessage
	err := d.Decode(&b)
	if err != nil {
		return err
	}

	return unmarshaler.Unmarshal([]byte(b), p)
}

func decodeNonProtoField(d *json.Decoder, unmarshaler UnmarshalOptions, v interface{}) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("%T is not a pointer", v)
	}
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}
		if rv.Type().ConvertibleTo(typeProtoMessage) {
			// Decode into bytes for marshalling
			var b json.RawMessage
			err := d.Decode(&b)
			if err != nil {
				return err
			}

			return unmarshaler.Unmarshal([]byte(b), rv.Interface().(proto.Message))
		}
		rv = rv.Elem()
	}
	if rv.Kind() == reflect.Map {
		if rv.IsNil() {
			rv.Set(reflect.MakeMap(rv.Type()))
		}
		conv, ok := convFromType[rv.Type().Key().Kind()]
		if !ok {
			return fmt.Errorf("unsupported type of map field key: %v", rv.Type().Key())
		}

		m := make(map[string]*json.RawMessage)
		if err := d.Decode(&m); err != nil {
			return err
		}
		for k, v := range m {
			result := conv.Call([]reflect.Value{reflect.ValueOf(k)})
			if err := result[1].Interface(); err != nil {
				return err.(error)
			}
			bk := result[0]
			bv := reflect.New(rv.Type().Elem())
			if err := unmarshalJSONPb([]byte(*v), unmarshaler, bv.Interface()); err != nil {
				return err
			}
			rv.SetMapIndex(bk, bv.Elem())
		}
		return nil
	}
	if rv.Kind() == reflect.Slice {
		var sl []json.RawMessage
		if err := d.Decode(&sl); err != nil {
			return err
		}
		if sl != nil {
			rv.Set(reflect.MakeSlice(rv.Type(), 0, 0))
		}
		for _, item := range sl {
			bv := reflect.New(rv.Type().Elem())
			if err := unmarshalJSONPb([]byte(item), unmarshaler, bv.Interface()); err != nil {
				return err
			}
			rv.Set(reflect.Append(rv, bv.Elem()))
		}
		return nil
	}
	if _, ok := rv.Interface().(protoEnum); ok {
		var repr interface{}
		if err := d.Decode(&repr); err != nil {
			return err
		}
		switch v := repr.(type) {
		case string:
			// TODO(yugui) Should use proto.StructProperties?
			return fmt.Errorf("unmarshaling of symbolic enum %q not supported: %T", repr, rv.Interface())
		case float64:
			rv.Set(reflect.ValueOf(int32(v)).Convert(rv.Type()))
			return nil
		default:
			return fmt.Errorf("cannot assign %#v into Go type %T", repr, rv.Interface())
		}
	}
	return d.Decode(v)
}

type protoEnum interface {
	fmt.Stringer
	EnumDescriptor() ([]byte, []int)
}

var typeProtoMessage = reflect.TypeOf((*proto.Message)(nil)).Elem()

// Delimiter for newline encoded JSON streams.
func (j *JSONPbAES) Delimiter() []byte {
	return []byte("\n")
}

var (
	convFromType = map[reflect.Kind]reflect.Value{
		reflect.String:  reflect.ValueOf(grpcgw.String),
		reflect.Bool:    reflect.ValueOf(grpcgw.Bool),
		reflect.Float64: reflect.ValueOf(grpcgw.Float64),
		reflect.Float32: reflect.ValueOf(grpcgw.Float32),
		reflect.Int64:   reflect.ValueOf(grpcgw.Int64),
		reflect.Int32:   reflect.ValueOf(grpcgw.Int32),
		reflect.Uint64:  reflect.ValueOf(grpcgw.Uint64),
		reflect.Uint32:  reflect.ValueOf(grpcgw.Uint32),
		reflect.Slice:   reflect.ValueOf(grpcgw.Bytes),
	}
)
