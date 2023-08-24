package db

import (
    "encoding/hex"
    "fmt"
    "os"
    "reflect"
    "strconv"
    "strings"

    "racfudit/common"
    "racfudit/decode"
    "racfudit/sections"
)

type Segment struct {
    Name string
    ID   uint8

    Address      decode.Address
    PhysicalSize uint32
    LogicalSize  uint32

    Raw  string
    Data reflect.Value
}

func NewSegment(name string, id uint8, addr decode.Address, psize uint32, lsize uint32, raw string, v *reflect.Value) *Segment {
    return &Segment{name, id, addr, psize, lsize, raw, *v}
}

type ProfileType struct {
    Name string
    ID   uint8
}

func (p *ProfileType) String() string {
    return fmt.Sprintf("%s; %d", p.Name, p.ID)
}

// Main structure of runtime DB
type Profile struct {
    Name     string
    Type     ProfileType
    Segments []Segment
}

func NewProfile(name string, tname string, tid uint8) *Profile {
    p := Profile{Name: name, Type: ProfileType{tname, tid}}
    p.Segments = make([]Segment, 0)
    return &p
}

// Convert Profile to string (for dumping as plain text)
func (p *Profile) String() string {
    retVal := fmt.Sprintf("Profile: %s (%v)\n", p.Name, &p.Type)
    for i, s := range p.Segments {
        retVal += fmt.Sprintf("\t[%d] Segment: %s (%d)\n", i+1, s.Name, s.ID)
        retVal += fmt.Sprintf("\t\tOffset: %v ; Physical Size: %d (0x%x) ; Logical Size: %d (0x%x)\n",
            &s.Address, s.PhysicalSize, s.PhysicalSize, s.LogicalSize, s.LogicalSize)
        retVal += fmt.Sprintf("\t\tRaw: %s\n", s.Raw)

        sDataV := reflect.Indirect(s.Data)
        sDataT := reflect.TypeOf(sDataV.Interface())
        for i := 0; i < sDataV.NumField(); i++ {
            retVal += "\t\t"
            fValue := sDataV.Field(i)
            fType := sDataT.Field(i)

            // Check if field is a RepeatGroup field
            if fType.Type.Kind() == reflect.Slice &&
                fType.Type.Elem().Kind() == reflect.Struct &&
                strings.HasSuffix(fType.Name, "_RG") {

                if fValue.Len() == 0 {
                    retVal += fmt.Sprintf("%s: %v (%s)\n", fType.Name, fValue.Interface(), fType.Type.Elem())
                    continue
                }

                retVal += fmt.Sprintf("%s: (%s)\n", fType.Name, fType.Type)
                for i := 0; i < fValue.Len(); i++ {
                    retVal += fmt.Sprintf("\t\t\t[%d]: ", i)
                    for j := 0; j < fValue.Index(i).NumField(); j++ {
                        rgFieldV := fValue.Index(i).Field(j)
                        rgFieldT := fType.Type.Elem().Field(j)
                        retVal += fmt.Sprintf("%s: %s\n", rgFieldT.Name, DumpFieldWithHex(rgFieldV))
                        if j < fValue.Index(i).NumField()-1 {
                            retVal += fmt.Sprintf("\t\t\t\t")
                        }
                    }
                }
            } else {
                retVal += fmt.Sprintf("%s: %s\n", fType.Name, DumpFieldWithHex(fValue))
            }
        }
    }
    return retVal
}

// Parse RACF DB and create Profile list in memory (runtime DB)
func ParseRACF(filename string) (map[string]map[string]reflect.Type, []*Profile, error) {
    // Read RACF content
    data, err := os.ReadFile(filename)
    if err != nil {
        return nil, nil, fmt.Errorf("can not open RACF DB file: %v\n", err)
    }

    common.Log.Info("Extracting Inventory Control Block (ICB)")
    icb, err := sections.ExtractICB(data)
    if err != nil {
        return nil, nil, err
    }
    common.Log.Debug("%v", icb)

    common.Log.Info("Extracting Templates")
    templates := make(map[uint8]sections.Template)
    templateNames := make(map[uint8]string) // Used to relate template Name and template Number from icb.ICBTEMP (field ICTMPN)
    for _, th := range icb.ICBTEMP {
        var t sections.Template
        if th.ICTMPRBA == 0 {
            break
        }
        if err := t.UnmarshalBinary(data[th.ICTMPRBA : uint64(th.ICTMPRBA)+uint64(th.ICTMPL)]); err != nil {
            return nil, nil, fmt.Errorf("can not extract template [%v: %s]: %v\n", &th.ICTMPRBA, t.Name(), err)
        }

        if _, ok := templates[th.ICTMPN]; !ok {
            templates[th.ICTMPN] = t
            templateNames[th.ICTMPN] = t.Name()
        } else {
            templates[th.ICTMPN] = append(templates[th.ICTMPN], t...)
        }

        common.Log.Debug("%s template (Offset: %v; Size: %d)\n", t.Name(), &th.ICTMPRBA, th.ICTMPL)
    }
    for i, t := range templates {
        common.Log.Debug("[%d] %v", i, &t)
    }

    common.Log.Info("Generating Profile structure based on RACF templates")
    profileStructs := make(map[string]map[string]reflect.Type)
    for _, t := range templates {
        common.Log.Debug("Creating structure for profile template %s", t.Name())
        //profileStructs[t.Name()] = sections.CreateProfileStruct(&t)
        profileStructs[t.Name()] = t.ToType()
    }
    for k, v := range profileStructs {
        common.Log.Debug("Dynamic structure for profile template %s: \n\t%v\n", k, &v)
    }

    common.Log.Info("Extracting Index Blocks")
    ibs := make([]sections.IndBlk, 0)
    for IndBlkAddr := icb.ICISSRBA; IndBlkAddr != 0; {
        var ib sections.IndBlk
        if err := ib.UnmarshalBinary(data[IndBlkAddr : IndBlkAddr+0x1000]); err != nil { // 0x1000 is size of index block
            return nil, nil, fmt.Errorf("can not extract index blocks [%v]: %v\n", &IndBlkAddr, err)
        }
        ibs = append(ibs, ib)
        IndBlkAddr = ib.SSC.RBA
    }
    for _, ib := range ibs {
        common.Log.Debug("%v", &ib)
    }

    common.Log.Info("Extracting Profiles")
    profiles := make([]*Profile, 0)
    for _, ib := range ibs {
        for _, e := range ib.Entries {
            p := NewProfile(e.Name.String(), templateNames[e.Type], e.Type)
            for _, d := range e.Data.Data {
                common.Log.Debug("Extracting profile %s (Offset: %v; Type: %d [%s]; Segment Type: %d)\n",
                    e.Name.String(), &d.RBA, e.Type, templateNames[e.Type], d.Id)

                profileSegmentRBA := d.RBA

                var ps sections.ProfileSegment
                if err := ps.UnmarshalBinary(data[profileSegmentRBA:]); err != nil {
                    common.Log.Warning("Can not extract segment %s-%s [%v]:%v\n",
                        e.Name.String(), templateNames[e.Type], &d.RBA, err)
                    continue
                }

                sValue, err := ps.ToValue(templateNames[e.Type], templates[e.Type], profileStructs)
                if err != nil {
                    common.Log.Warning("Can not extract segment %s-%s [%v]:%v\n",
                        e.Name.String(), templateNames[e.Type], &d.RBA, err)
                    continue
                }

                s := NewSegment(
                    strings.TrimSpace(ps.Hdr.SegmentName.String()),
                    d.Id,
                    d.RBA,
                    ps.Hdr.PhysicLen,
                    ps.Hdr.LogicLen,
                    hex.EncodeToString(data[profileSegmentRBA:uint64(profileSegmentRBA)+uint64(ps.Hdr.LogicLen)]),
                    sValue,
                )
                p.Segments = append(p.Segments, *s)
            }
            profiles = append(profiles, p)
        }
    }

    return profileStructs, profiles, nil
}

// Get string representation of reflect.Value from runtime DB
func DumpField(val reflect.Value) string {
    var retVal string
    switch v := val.Interface().(type) {
    case uint8, uint16, uint64:
        retVal = fmt.Sprintf("%d", v)
    case uint32:
        if t, ok := isTime(v); ok {
            retVal = t
        } else {
            retVal = fmt.Sprintf("%d", v)
        }
    case decode.EBCDICStr:
        if v.IsPrint() {
            retVal = fmt.Sprintf("%s", v.String())
        } else {
            retVal = fmt.Sprintf("%s", v.Hex())
        }
    case decode.HexStr:
        retVal = fmt.Sprintf("%v", &v)
    case decode.Date:
        retVal = fmt.Sprintf("%v", &v)
    case decode.Time:
        retVal = fmt.Sprintf("%v", &v)
    case decode.Flag:
        retVal = fmt.Sprintf("%v", &v)
    case []byte:
        retVal = fmt.Sprintf("%v", v)
    }
    return retVal
}

// Get string representation of reflect.Value from runtime DB with hex
func DumpFieldWithHex(val reflect.Value) string {
    var retVal string
    switch v := val.Interface().(type) {
    case uint8, uint16, uint32, uint64:
        retVal = fmt.Sprintf("%d (%x)", v, v)
    case decode.EBCDICStr:
        if v.IsPrint() {
            retVal = fmt.Sprintf("%s (%s)", v.String(), v.Hex())
        } else {
            retVal = fmt.Sprintf("%s", v.Hex())
        }
    case decode.HexStr:
        retVal = fmt.Sprintf("%v", &v)
    case decode.Date:
        retVal = fmt.Sprintf("%s (%s)", v.String(), v.Hex())
    case decode.Time:
        retVal = fmt.Sprintf("%s (%s)", v.String(), v.Hex())
    case decode.Flag:
        retVal = fmt.Sprintf("%s (%s)", v.String(), v.Hex())
    case []byte:
        retVal = fmt.Sprintf("%v", v)
    }
    return retVal
}

// Check if a integer represent time (hhmmssms)
// Возможно стоит удалить эту херню
func isTime(v uint32) (string, bool) {
    if v < 0xff {
        return "", false
    }

    // Check the first byte as hours
    hh, err := strconv.Atoi(fmt.Sprintf("%02x", (v>>24)&0xff))
    if err != nil || hh < 0 || hh > 24 {
        return "", false
    }
    // Check the second byte as minutes
    mm, err := strconv.Atoi(fmt.Sprintf("%02x", (v>>16)&0xff))
    if err != nil || mm < 0 || mm > 60 {
        return "", false
    }
    // Check the third byte as seconds
    ss, err := strconv.Atoi(fmt.Sprintf("%02x", (v>>8)&0xff))
    if err != nil || ss < 0 || ss > 60 {
        return "", false
    }
    // Check the forth byte as miliseconds
    ms, err := strconv.Atoi(fmt.Sprintf("%02x", (v>>8)&0xff))
    if err != nil || ms < 0 || ms > 60 {
        return "", false
    }

    return fmt.Sprintf("%d:%02d:%02d (%02d ms)", hh, mm, ss, ms), true
}
