package sections

import (
	"fmt"
	"reflect"
	"strings"

	"racfudit/common"
	"racfudit/decode"
)

// ToDO: Maybe be changed for other RACF version. Need to check
const TEMPLATE_SIZE = 17

// https://www.ibm.com/docs/en/zos/2.2.0?topic=templates-format-field-definitions
type TemplateField struct {
	Name         decode.EBCDICStr `racf:"size=8"` // Field name
	ID           uint8            // Reference number if the field
	Flag1        uint8            // First field flag
	Flag2        uint8            // Second field flag
	_            uint8            `racf:"size=1"` // Reserved
	Len          uint32           // Field length
	DefaultValue uint8            // Field default
}

func (f *TemplateField) String() string {
	retVal := fmt.Sprintf("[%d] %v (Hex: %v)\n", f.ID, &f.Name, f.Name.Hex())
	retVal += fmt.Sprintf("\tFlag1=%d; Flag2=%d; Len=%d; DefaultValue=%d; ", f.Flag1, f.Flag2, f.Len, f.DefaultValue)
	return retVal
}

func (f *TemplateField) UnmarshalBinary(data []byte) error {
	t := reflect.TypeOf(*f)
	v := reflect.ValueOf(f).Elem()
	if len(data) < decode.Size(v) {
		return fmt.Errorf("Field.UnmarshalBinary: not enough data")
	}

	for i, ptr := 0, 0; i < t.NumField(); i++ {
		curT := t.Field(i)
		curV := v.Field(i)
		tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
		size, err := decode.DecodeValue(data[ptr:], &curV, tags)
		if err != nil {
			return fmt.Errorf("Field.UnmarshalBinary: %v", err)
		}
		ptr += size
	}
	return nil
}

func (f *TemplateField) IsSegmentName() bool {
	if f.ID == 1 && f.Flag1 == 0 && f.Flag2 == 0 && f.Len == 0 && f.DefaultValue == 0 {
		return true
	}
	return false
}

func (f *TemplateField) IsRepeatGroup() bool {
	if f.Flag1&0x10 == 0x10 {
		return true
	}
	return false
}

func (f *TemplateField) IsRepeatGroupMember() bool {
	if f.Flag1&0x80 == 0x80 {
		return true
	}
	return false
}

func (f *TemplateField) isCombinationField() bool {
	if f.Flag1&0x40 == 0x40 {
		return true
	}
	return false
}

func (f *TemplateField) NameTrim() string {
	return strings.TrimSpace(f.Name.String())
}

func (f *TemplateField) ToType(tmpName string) reflect.Type {
	if common.Opt.UseFieldDB {
		// Search Template field in predefined list
		for k, v := range decode.FieldTypes[tmpName] {
			if f.NameTrim() == k {
				switch v {
				case decode.T_INT:
					if f.Len == 1 {
						return reflect.TypeOf(uint8(0))
					} else if f.Len == 2 {
						return reflect.TypeOf(uint16(0))
					} else if f.Len == 4 {
						return reflect.TypeOf(uint32(0))
					}
					return reflect.TypeOf(uint64(0))
				case decode.T_СHAR:
					if f.Flag1&0x04 == 0x04 { // The field (for example, PASSWORD) is encrypted.
						return reflect.TypeOf(decode.HexStr{})
					}
					return reflect.TypeOf(decode.EBCDICStr{})
				case decode.T_DATE:
					if f.Flag2&0x20 == 0x20 { // This field represents a 3-byte date field.
						return reflect.TypeOf(decode.Date{})
					}
					// ToDo: define four byte Date
					return reflect.TypeOf(decode.Date{})
				case decode.T_TIME:
					return reflect.TypeOf(decode.Time{})
				case decode.T_BIN:
					if f.Flag1&0x20 == 0x20 { // The field is a flag byte.
						return reflect.TypeOf(decode.Flag{})
					}
					return reflect.TypeOf(decode.HexStr{}) // Just for hex representation
				case decode.T_FLAG:
					return reflect.TypeOf(decode.Flag{})
				}
			}
		}
	}

	// Try to detect type if field isn't in decode.FieldTypes
	return f.ToTypeWithoutFieldDB()
}

// Detect type if field isn't in field DB (staticly impossible to define Time fields)
func (f *TemplateField) ToTypeWithoutFieldDB() reflect.Type {
	if f.Flag1&0x04 == 0x04 { // The field (for example, PASSWORD) is encrypted.
		return reflect.TypeOf(decode.HexStr{})
	} else if f.Flag2&0x20 == 0x20 { // This field represents a 3-byte date field.
		return reflect.TypeOf(decode.Date{})
	} else if f.Flag1&0x20 == 0x20 { // This field is a flag byte.
		return reflect.TypeOf(decode.Flag{})
	} else if f.Len == 1 { // different integer fields
		return reflect.TypeOf(uint8(0))
	} else if f.Len == 2 {
		return reflect.TypeOf(uint16(0))
	} else if f.Len == 4 {
		return reflect.TypeOf(uint32(0))
	} else if f.Len >= 8 || f.Len == 0 { // This is char field
		return reflect.TypeOf(decode.EBCDICStr{})
	} else {
		return reflect.TypeOf([]byte{0}) // default option
	}
}

type Template []*TemplateField

func (tmp *Template) String() string {
	var retVal string
	for i, f := range *tmp {
		if i == 0 {
			retVal += fmt.Sprintf("Template %v\n", &f.Name)
		}
		retVal += fmt.Sprintf("%v\n", f)
	}

	return retVal
}

func (tmp *Template) UnmarshalBinary(data []byte) error {
	for ptr := 0; ptr < len(data); ptr += TEMPLATE_SIZE {
		var f TemplateField
		if err := f.UnmarshalBinary(data[ptr : ptr+TEMPLATE_SIZE]); err != nil {
			return err
		}
		*tmp = append(*tmp, &f)
	}
	return nil
}

func (tmp *Template) Name() string {
	return []*TemplateField(*tmp)[0].NameTrim()
}

func (tmp *Template) FieldByID(id uint8, sname string) (*TemplateField, bool) {
	var segmentFound bool
	if sname == "BASE" {
		segmentFound = true
	}
	for _, f := range *tmp {
		if !segmentFound {
			if f.IsSegmentName() && (f.NameTrim() == sname) {
				segmentFound = true
			}
			continue
		}
		if f.ID == id {
			return f, true
		}
	}
	return nil, false
}

// Convert Template to map of reflect.Type where each item corresponds to a profile segment structure
func (tmp *Template) ToType() map[string]reflect.Type {
	retVal := make(map[string]reflect.Type)    // result map
	fields := make([]reflect.StructField, 0)   // StructFields for segment structure
	rgFields := make([]reflect.StructField, 0) // StructFields for RepeatGroup structure

	var sName string
	var rgName string
	var isRepeatGroup bool

	for i, f := range *tmp {
		common.Log.Debug("Processing field [%d] %v", f.ID, &f.Name)

		// Skip CombinationField
		if f.isCombinationField() {
			continue
		}

		// Check that current field is a segment name
		if f.IsSegmentName() {
			// Create reflect struct for previous segment if fields is not empty
			if len(fields) > 0 {
				retVal[sName] = reflect.StructOf(fields)
				fields = make([]reflect.StructField, 0)
			}
			// Set segment name
			if i == 0 {
				sName = "BASE"
			} else {
				sName = f.NameTrim()
			}
			continue
		}

		// Handling RepeatGroup fields
		if isRepeatGroup {
			if f.IsRepeatGroupMember() {
				// Add the field into rgFields if it is a RepeatGroup field
				rgFields = append(rgFields, reflect.StructField{Name: f.NameTrim(), Type: f.ToType(tmp.Name())})
				continue
			} else {
				// Otherwise create a struct for RepeatGroup fields and save it into fields slice
				isRepeatGroup = false
				rgStruct := reflect.StructOf(rgFields)
				fields = append(fields, reflect.StructField{Name: rgName, Type: reflect.SliceOf(rgStruct)})
				rgFields = make([]reflect.StructField, 0)
			}
		}

		// Check that RepeatGroup is started
		if f.IsRepeatGroup() {
			isRepeatGroup = true
			rgName = fmt.Sprintf("%s_RG", f.NameTrim())
		}

		// Skip nameless field in template (e.x. COMBINATION fields in GENERAL segment (num 83; after TVTOC))
		if len(f.NameTrim()) > 0 {
			fields = append(fields, reflect.StructField{Name: f.NameTrim(), Type: f.ToType(tmp.Name())})

		}

	}
	return retVal
}
