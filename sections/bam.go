package sections

import (
    "fmt"
    "reflect"

    "racfudit/decode"
)

// https://www.ibm.com/docs/en/zos/2.1.0?topic=blocks-bam-block-header
type BAMBlk struct {
    Prev  decode.Address `racf:"size=6"` // RBA of the previous BAM block (or 0 if this is the first block)
    Next  decode.Address `racf:"size=6"` // RBA of the next BAM block (or 0 if this is the last block)
    First decode.Address `racf:"size=6"` // RBA of the first 4KB block whose space this BAM block defines.
    Num   uint16                         // Number of 4KB blocks whose space this BAM block defines.
    Mask  []uint16 `racf:"size=Num"`     // Two-byte block masks
}

func (bam *BAMBlk) String() string {
    return fmt.Sprintf("PrevBlk: %v; NextBlk: %v; Address of first block: %v; Number of blocks: %v", &bam.Prev, &bam.Next, &bam.First, bam.Num)
}

func (bam *BAMBlk) UnmarshalBinary(data []byte) error {
    t := reflect.TypeOf(*bam)
    v := reflect.ValueOf(bam).Elem()
    if len(data) < decode.Size(v) {
        return fmt.Errorf("BAMBlkHdr.UnmarshalBinary: not enough data")
    }

    for i, ptr := 0, 0; i < t.NumField(); i++ {
        curT := t.Field(i)
        curV := v.Field(i)
        tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
        size, err := decode.DecodeValue(data[ptr:], &curV, tags)
        if err != nil {
            return fmt.Errorf("BAMBlkHdr.UnmarshalBinary: %v", err)
        }
        ptr += size
    }
    return nil
}
