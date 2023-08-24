package decode

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type FieldTag map[string]int

func ParseTag(tag string, root reflect.Value) (FieldTag, error) {
	ft := make(FieldTag)
	fields := strings.Split(tag, ",")
	for _, f := range fields {
		parts := strings.Split(f, "=")
		ft[parts[0]] = 0
		if len(parts) == 2 {
			if v, err := strconv.Atoi(parts[1]); err != nil {
				v := root.FieldByName(parts[1])
				if v == (reflect.Value{}) {
					return ft, fmt.Errorf("decode.ParseTagNew: no field %q", parts[1])
				}
				switch v := v.Interface().(type) {
				case uint8:
					ft[parts[0]] = int(v)
				case uint16:
					ft[parts[0]] = int(v)
				case uint32:
					ft[parts[0]] = int(v)
				}
			} else {
				ft[parts[0]] = v
			}
		}
	}
	return ft, nil
}

func zeroPadding(a []byte, size int) []byte {
	retVal := make([]byte, 0)
	for i := len(a); i < size; i++ {
		retVal = append(retVal, 0)
	}
	retVal = append(retVal, a...)
	return retVal
}
