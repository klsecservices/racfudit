package sections

import (
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "reflect"
    "strings"

    "racfudit/common"
    "racfudit/decode"
)

type ProfileSegmentRepeatGroupField struct {
    Len   ProfileSegmentFieldLength
    Value []byte
}

func (rpf *ProfileSegmentRepeatGroupField) UnmarshalBinary(data []byte) error {
    rpf.Len = ProfileSegmentFieldLength(data[0])
    if rpf.Len&0x80 != 0 {
        if len(data) < 4 {
            return fmt.Errorf("ProfileSegmentRepeatGroupField.UnmarshalBinary: not enough data for field Length")
        }
        rpf.Len = ProfileSegmentFieldLength(binary.BigEndian.Uint32(data))
    }
    rpf.Value = data[rpf.Len.Size() : rpf.Len.Size()+rpf.Len.Int()]
    return nil
}

type ProfileSegmentRepeatGroup struct {
    Num    uint8
    Fields []ProfileSegmentRepeatGroupField
}

func (rp *ProfileSegmentRepeatGroup) UnmarshalBinary(data []byte) error {
    rp.Num = data[0]
    rp.Fields = make([]ProfileSegmentRepeatGroupField, rp.Num)
    ptr := 1
    for i := 0; i < int(rp.Num); i++ {
        var f ProfileSegmentRepeatGroupField
        if err := f.UnmarshalBinary(data[ptr:]); err != nil {
            return err
        }
        rp.Fields[i] = f
        ptr += f.Len.Size() + f.Len.Int()
    }
    return nil
}

func (rp *ProfileSegmentRepeatGroup) Size() int {
    retVal := 1
    for i := 0; i < int(rp.Num); i++ {
        retVal += rp.Fields[i].Len.Size() + rp.Fields[i].Len.Int()
    }
    return retVal
}

type ProfileSegmentHdr struct {
    Magic          byte             // 0x83 Record identifier.
    PhysicLen      uint32           // Physical length of this record, in bytes.
    LogicLen       uint32           // Logical record length. Length, in bytes, of the portion of the record that actually contains data.
    SegmentName    decode.EBCDICStr `racf:"size=8"` // Segment name.
    ProfileNameLen uint16           // Length of profile name
    _              []byte           `racf:"size=1"`              // Reserved
    ProfileName    decode.EBCDICStr `racf:"size=ProfileNameLen"` // Profile name
}

func (psh *ProfileSegmentHdr) String() string {
    retVal := "Profile Segment Header:\n"
    retVal += fmt.Sprintf("\tPhysical length: %d (%08x)\n", psh.PhysicLen, psh.PhysicLen)
    retVal += fmt.Sprintf("\tLogical length: %d (%08x)\n", psh.LogicLen, psh.LogicLen)
    retVal += fmt.Sprintf("\tSegment name: %v\n", &psh.SegmentName)
    retVal += fmt.Sprintf("\tProfile name length: %d (%04x)\n", psh.ProfileNameLen, psh.ProfileNameLen)
    retVal += fmt.Sprintf("\tProfile name: %v", &psh.ProfileName)
    return retVal
}

func (psh *ProfileSegmentHdr) UnmarshalBinary(data []byte) error {
    t := reflect.TypeOf(*psh)
    v := reflect.ValueOf(psh).Elem()
    if len(data) < decode.Size(v) {
        return fmt.Errorf("ProfileSegmentHdr.UnmarshalBinary: not enough data")
    }

    for i, ptr := 0, 0; i < t.NumField(); i++ {
        curT := t.Field(i)
        curV := v.Field(i)
        tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
        size, err := decode.DecodeValue(data[ptr:], &curV, tags)
        if err != nil {
            return fmt.Errorf("ProfileSegmentHdr.UnmarshalBinary: %v", err)
        }
        ptr += size
    }
    return nil
}

type ProfileSegmentFieldLength uint32

func (l *ProfileSegmentFieldLength) Int() int {
    if *l&0x80000000 != 0 {
        return int(*l & 0x7fffffff)
    }
    return int(*l)
}

func (l *ProfileSegmentFieldLength) String() string {
    return fmt.Sprintf("%d", l.Int())
}

func (l *ProfileSegmentFieldLength) Size() int {
    if *l&0x80000000 != 0 {
        return 4
    }
    return 1
}

type ProfileSegmentField struct {
    Id    uint8
    Len   ProfileSegmentFieldLength
    Value []byte
}

func (pfs *ProfileSegmentField) String() string {
    var retVal string
    retVal += fmt.Sprintf("Id: %d (0x%02x);", pfs.Id, pfs.Id)
    retVal += fmt.Sprintf(" Length: %s;", &pfs.Len)
    retVal += fmt.Sprintf(" Value (in hex): %s\n", hex.EncodeToString(pfs.Value))
    return retVal
}

func (pfs *ProfileSegmentField) UnmarshalBinary(data []byte) error {
    if len(data) < 2 {
        return fmt.Errorf("ProfileSegmentField.UnmarshalBinary: not enough data")
    }
    pfs.Id = data[0]
    ptr := 1

    pfs.Len = ProfileSegmentFieldLength(data[1])
    if pfs.Len&0x80 != 0 {
        if len(data) < 5 {
            return fmt.Errorf("ProfileSegmentField.UnmarshalBinary: not enough data for field Length")
        }
        pfs.Len = ProfileSegmentFieldLength(binary.BigEndian.Uint32(data[1:]))
        ptr += 4
    } else {
        ptr += 1
    }

    if len(data) < ptr+pfs.Len.Int() {
        return fmt.Errorf("ProfileSegmentField.UnmarshalBinary: not enough data for field Value")
    }
    pfs.Value = data[ptr : ptr+pfs.Len.Int()]
    return nil
}

type ProfileSegment struct {
    Hdr    ProfileSegmentHdr
    Fields []ProfileSegmentField
}

func (ps *ProfileSegment) UnmarshalBinary(data []byte) error {
    // Restore Header
    if err := ps.Hdr.UnmarshalBinary(data); err != nil {
        return fmt.Errorf("ProfileSegment.UnmarshalBinary: %v", err)
    }

    // Restore Profile segment field from data
    for ptr := decode.Size(reflect.ValueOf(ps.Hdr)); ptr < int(ps.Hdr.LogicLen); {

        var f ProfileSegmentField
        if err := f.UnmarshalBinary(data[ptr:]); err != nil {
            return fmt.Errorf("ProfileSegment.UnmarshalBinary: %v", err)
        }
        common.Log.Debug("Extracted segment field: %v", &f)
        ps.Fields = append(ps.Fields, f)

        // Move data pointer to the next Profile segment field
        ptr += 1 + f.Len.Size() + f.Len.Int()
    }
    return nil
}

// Convert ProfileSegment to reflect.Value according profile structure
func (ps *ProfileSegment) ToValue(profileType string, template Template, profileStructs map[string]map[string]reflect.Type) (*reflect.Value, error) {
    sName := strings.TrimSpace(ps.Hdr.SegmentName.String())
    sType, ok := profileStructs[profileType][sName]
    if !ok || sType.Kind() != reflect.Struct {
        return nil, fmt.Errorf("can not find segment name %q in dynamic profile structures (%s) or segment type is not a structure", sName, profileType)
    }
    sValue := reflect.New(sType)

    for _, f := range ps.Fields {
        // Convert and save Profile segment field into Template profile structure
        tf, ok := template.FieldByID(f.Id, sName)
        if !ok {
            common.Log.Warning("Skipping handling of field ID=%d (Profile: %v, Segment: %v): field not found in the Template ptrofile structure",
                f.Id, &ps.Hdr.ProfileName, sName)
            continue
        }
        fName := tf.NameTrim()
        fValue := sValue.Elem().FieldByName(fName)
        if !fValue.CanSet() {
            common.Log.Error("Skipping handling of field %s (Profile: %v, Segment: %v): field is not found in the releted dynamic profile structure",
                fName, &ps.Hdr.ProfileName, sName)
            continue
        }
        if err := setProfileSegmentField(&fValue, f.Value, f.Len.Int()); err != nil {
            common.Log.Warning("Zero value was set for field %s (Profile: %v, Segment: %s): %v\n",
                fName, &ps.Hdr.ProfileName, sName, err)
        }

        // Handle RepeatGroup fields
        if tf.IsRepeatGroup() {
            rpName := fmt.Sprintf("%s_RG", fName)
            rpCount := fValue.Uint()
            rpPtr := decode.Size(fValue)

            // Check the RepeatGroup field exists in the structure
            rpSliceT, ok := sType.FieldByName(rpName)
            if !ok {
                common.Log.Warning("Skipping handling of RepeatGroup field %s (Profile: %v, Segment: %s): field not found in the Template ptrofile structure",
                    rpName, &ps.Hdr.ProfileName, sName)
                continue
            }
            rpType := rpSliceT.Type.Elem()
            if rpType.Kind() != reflect.Struct {
                common.Log.Warning("Skipping handling of RepeatGroup field %s (Profile: %v, Segment: %s): field is not a structure",
                    rpName, profileType)
                continue
            }

            // Prepare slice for RepeatGroup Field
            rpSliceV := sValue.Elem().FieldByName(rpName)
            rpSliceV.Set(reflect.MakeSlice(rpSliceT.Type, int(rpCount), int(rpCount)))

            // Extracting RepeatGroup fields and save them as a corresponding structure
            for i := 0; i < int(rpCount); i++ {

                // Restore RepeatGroup field from data
                var rp ProfileSegmentRepeatGroup
                if err := rp.UnmarshalBinary(f.Value[rpPtr:]); err != nil {
                    common.Log.Error("Error while handling item %d of RepeatGroup %s (Profile: %v, Segment: %s): %v",
                        i, rpName, &ps.Hdr.ProfileName, sName, err)
                    break
                }

                // Move data pointer to the next RepeatGroup field
                rpPtr += rp.Size()

                // Create object of RepeatGroup structure and fill it
                rpValue := reflect.New(rpType)
                for j := 0; j < rpType.NumField(); j++ {
                    rpFieldV := rpValue.Elem().Field(j)
                    if err := setProfileSegmentField(&rpFieldV, rp.Fields[j].Value, rp.Fields[j].Len.Int()); err != nil {
                        common.Log.Warning("Zero value was set for field %s of RepeatGroup item %s[%d] (Profile: %v, Segment: %s): %v\n",
                            rpType.Field(j).Name, rpName, i, &ps.Hdr.ProfileName, sName, err)
                    }
                }

                // Save object of RepeatGroup structure into a result slice
                e := rpSliceV.Index(i)
                e.Set(rpValue.Elem())
            }
        }
    }

    return &sValue, nil
}

func setProfileSegmentField(v *reflect.Value, data []byte, length int) error {
    var err error
    switch v.Kind() {
    case reflect.Uint8:
        if len(data) == 0 {
            v.SetUint(uint64(0))
            err = fmt.Errorf("not enough data to set Uint8")
        } else {
            v.SetUint(uint64(data[0]))
        }
    case reflect.Uint16:
        if len(data) < 2 {
            v.SetUint(uint64(0))
            err = fmt.Errorf("not enough data to set Uint16")
        } else {
            v.SetUint(uint64(binary.BigEndian.Uint16(data)))
        }
    case reflect.Uint32:
        if len(data) < 4 {
            v.SetUint(uint64(0))
            err = fmt.Errorf("not enough data to set Uint32")
        } else {
            v.SetUint(uint64(binary.BigEndian.Uint32(data)))
        }
    case reflect.Uint64: // just in case
        if len(data) < 8 {
            v.SetUint(uint64(0))
            err = fmt.Errorf("not enough data to set Uint64")
        } else {
            v.SetUint(uint64(binary.BigEndian.Uint64(data)))
        }
    case reflect.Array: // [4]byte Time
        for i := 0; i < v.Len(); i++ {
            e := v.Index(i)
            if i < len(data) {
                e.SetUint(uint64(data[i]))
            } else {
                e.SetUint(uint64(0))
                err = fmt.Errorf("not enough data to set Array")
            }
        }
    case reflect.Slice: // []byte EBCDICStr; []byte EncStr; []byte Flag; []byte Date
        v.Set(reflect.MakeSlice(reflect.TypeOf(v.Interface()), int(length), int(length)))
        for i := 0; i < int(length); i++ {
            e := v.Index(i)
            if i < len(data) {
                e.SetUint(uint64(data[i]))
            } else {
                e.SetUint(uint64(0))
                err = fmt.Errorf("not enough data to set Slice")
            }
        }
    }
    return err
}
