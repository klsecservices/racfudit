package decode

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
)

func decode(data []byte, v *reflect.Value) {
	switch v.Kind() {
	case reflect.Uint8:
		v.SetUint(uint64(data[0]))
	case reflect.Int8:
		v.SetInt(int64(data[0]))
	case reflect.Uint16:
		v.SetUint(uint64(binary.BigEndian.Uint16(data)))
	case reflect.Int16:
		v.SetInt(int64(binary.BigEndian.Uint16(data)))
	case reflect.Uint32:
		v.SetUint(uint64(binary.BigEndian.Uint32(data)))
	case reflect.Int32:
		v.SetInt(int64(binary.BigEndian.Uint32(data)))
	case reflect.Uint64:
		v.SetUint(binary.BigEndian.Uint64(data))
	case reflect.Int64:
		v.SetInt(int64(binary.BigEndian.Uint64(data)))
	case reflect.Float32:
		v.SetFloat(float64(math.Float32frombits(binary.BigEndian.Uint32(data))))
	case reflect.Float64:
		v.SetFloat(math.Float64frombits(binary.BigEndian.Uint64(data)))
	case reflect.Array:
		for j := 0; j < v.Len(); j++ {
			e := v.Index(j)
			decode(data[4*j:], &e)
		}
	}
}

func DecodeValue(data []byte, v *reflect.Value, tags FieldTag) (int, error) {
	shift := -1

	if !v.CanSet() {
		if shift, ok := tags["size"]; ok {
			return shift, nil
		}
		return shift, fmt.Errorf("decode.DecodeValue: unknown size for anonymous field %v", v)
	}

	switch v.Kind() {
	case reflect.Bool:
		if size, ok := tags["size"]; ok {
			var n uint64
			switch size {
			case 1:
				n = uint64(data[0])
			case 2:
				n = uint64(binary.BigEndian.Uint16(data))
			case 4:
				n = uint64(binary.BigEndian.Uint32(data))
			}
			bitNum, ok := tags["bit"]
			if ok {
				v.SetBool((n >> ((8*size - 1) - bitNum) & 1) != 0)
			} else {
				v.SetBool(n != 0)
			}
			shift = 0
			if _, ok := tags["final"]; ok || bitNum == (8*size-1) {
				shift = size
			}
		} else {
			v.SetBool(data[0] != 0)
		}
	case reflect.Uint8:
		v.SetUint(uint64(data[0]))
	case reflect.Int8:
		v.SetInt(int64(data[0]))
	case reflect.Uint16:
		v.SetUint(uint64(binary.BigEndian.Uint16(data)))
	case reflect.Int16:
		v.SetInt(int64(binary.BigEndian.Uint16(data)))
	case reflect.Uint32:
		v.SetUint(uint64(binary.BigEndian.Uint32(data)))
	case reflect.Int32:
		v.SetInt(int64(binary.BigEndian.Uint32(data)))
	case reflect.Uint64:
		if size, ok := tags["size"]; ok {
			v.SetUint(binary.BigEndian.Uint64(zeroPadding(data[:size], 8)))
			shift = size
		} else {
			v.SetUint(binary.BigEndian.Uint64(data))
		}
	case reflect.Int64:
		if size, ok := tags["size"]; ok {
			v.SetUint(binary.BigEndian.Uint64(zeroPadding(data[:size], 8)))
			shift = size
		} else {
			v.SetInt(int64(binary.BigEndian.Uint64(data)))
		}
	case reflect.Float32:
		v.SetFloat(float64(math.Float32frombits(binary.BigEndian.Uint32(data))))
	case reflect.Float64:
		v.SetFloat(math.Float64frombits(binary.BigEndian.Uint64(data)))
	case reflect.Array:
		shift = 0
		for i := 0; i < v.Len(); i++ {
			e := v.Index(i)
			DecodeValue(data[Size(e)*i:], &e, tags) // Size(e) used here because element can have dynamic Size
			shift += Size(e)
		}
	case reflect.Slice:
		shift = 0
		if size, ok := tags["size"]; ok {
			v.Set(reflect.MakeSlice(reflect.TypeOf(v.Interface()), size, size))
			for i := 0; i < v.Len(); i++ {
				e := v.Index(i)
				DecodeValue(data[Size(e)*i:], &e, tags) // Size(e) used here because element can have dynamic Size
				shift += Size(e)
			}
		} else {
			return -1, fmt.Errorf("decode.DecodeValue: no size tag for slice field %v", v)
		}

	case reflect.Struct:
		shift = 0
		sT := reflect.TypeOf(v.Interface())
		for i := 0; i < sT.NumField(); i++ {
			curT := sT.Field(i)
			curV := v.Field(i)
			tags, _ := ParseTag(curT.Tag.Get("racf"), *v)
			size, err := DecodeValue(data[shift:], &curV, tags)
			if err != nil {
				return -1, fmt.Errorf("decode.DecodeValue: %v", err)
			}
			shift += size
		}
	}

	if shift == -1 {
		shift = Size(*v)
	}

	return shift, nil
}

func Size(v reflect.Value) int {
	var retVal int
	T := reflect.TypeOf(v.Interface())
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			tags, _ := ParseTag(T.Field(i).Tag.Get("racf"), v)
			if size, ok := tags["size"]; ok {
				retVal += size
			} else {
				retVal += Size(v.Field(i))
			}
		}
	case reflect.Array:
		for i := 0; i < T.Len(); i++ {
			retVal += Size(v.Index(i))
		}
	case reflect.Slice:
		for i := 0; i < T.Len(); i++ {
			retVal += Size(v.Index(i))
		}
	default:
		retVal = int(T.Size())
	}
	return retVal
}
