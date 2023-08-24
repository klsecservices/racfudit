package sections

import (
    "fmt"
    "reflect"

    "racfudit/decode"
)

// https://www.ibm.com/docs/en/zos/2.1.0?topic=blocks-overview

var IndexEntryIDs = map[uint8]string{0x21: "Normal index entry", 0x22: "Duplicate index entry", 0x23: "Alias index entry"}
var IndexEntryTypes = map[uint8]string{1: "Group", 2: "User", 4: "Data set", 5: "General resource"}
var IndexEntrySegmentIDsGroup = map[uint8]string{0x1: "BASE", 0x2: "DFP", 0x3: "OMVS", 0x4: "OVM", 0x5: "TME", 0x6: "CSDATA"}
var IndexEntrySegmentIDsUser = map[uint8]string{0x1: "BASE", 0x2: "DFP", 0x3: "TSO", 0x4: "CICS", 0x5: "LANGUAGE", 0x6: "OPERPARM",
    0x7: "WORKATTR", 0x8: "OMVS", 0x9: "NETVIEW", 0xA: "DCE", 0xB: "OVM", 0xC: "LNOTES", 0xD: "NDS", 0xE: "KERB", 0xF: "PROXY", 0x10: "EIM", 0x11: "CSDATA"}
var IndexEntrySegmentIDsDataSet = map[uint8]string{0x1: "BASE", 0x2: "DFP", 0x3: "TME"}
var IndexEntrySegmentIDsGeneral = map[uint8]string{0x1: "BASE", 0x2: "SESSION", 0x3: "DLFDATA", 0x4: "SSIGNON", 0x5: "STDATA", 0x6: "SVFMR",
    0x7: "CERTDATA", 0x8: "TME", 0x9: "KERB", 0xA: "PROXY", 0xB: "EIM", 0xC: "ALIAS", 0xD: "CDTINFO", 0xE: "ICTX", 0xF: "CFDEF", 0x10: "SIGVER", 0x11: "ICSF"}

var IndexEntrySegmentIDs = map[uint8]map[uint8]string{1: IndexEntrySegmentIDsGroup, 2: IndexEntrySegmentIDsUser, 4: IndexEntrySegmentIDsDataSet, 5: IndexEntrySegmentIDsGeneral}

type IndBlkHdr struct {
    Id1         uint8  // 0x8A Index block identifier
    Len         uint16 // 0x1000' Length of the index block
    Id2         uint8  // 0x4E Index block identifier
    FormatId    uint8  // 0x00 Format identifier for regular index block; 0x01 Format identifier for alias index block
    Level       uint8  // Index-level number (01-0A)
    OffsetLast  uint16 // Offset to the last entry in the index block. In a level-1 index block, the last entry is a sequence set chain pointer entry. In an upper-level index block, the last entry is the last index entry of the block
    OffsetFree  uint16 // Offset to free space in the index block
    OffsetTable uint16 // Offset to a table of index-entry offsets
    EntryNum    uint16 // Count of index entries in the block. This is also equivalent to the count of entries in the table of index-entry offsets (the bottom part of the block)
}

func (h *IndBlkHdr) String() string {
    return fmt.Sprintf("Id1: 0x%02x; Len: 0x%04x; Id2: 0x%02x; FormatId: 0x%02x; Level: 0x%02x; OffsetLast: 0x%04x; OffsetFree: 0x%04x; OffsetTable: 0x%04x; EntryNum: %d",
        h.Id1, h.Len, h.Id2, h.FormatId, h.Level, h.OffsetLast, h.OffsetFree, h.OffsetTable, h.EntryNum)
}

func (h *IndBlkHdr) UnmarshalBinary(data []byte) error {
    t := reflect.TypeOf(*h)
    v := reflect.ValueOf(h).Elem()
    if len(data) < decode.Size(v) {
        return fmt.Errorf("IndBlkHdr.UnmarshalBinary: not enough data")
    }

    for i, ptr := 0, 0; i < t.NumField(); i++ {
        curT := t.Field(i)
        curV := v.Field(i)
        tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
        size, err := decode.DecodeValue(data[ptr:], &curV, tags)
        if err != nil {
            return fmt.Errorf("IndBlkHdr.UnmarshalBinary: %v", err)
        }
        ptr += size
    }
    return nil
}

type SegmentData struct {
    Id  uint8          // Segment Identifier
    RBA decode.Address `racf:"size=6"` // RBA of the segment (or the next-lower-level index block)
}

type SegmentDataL1Reg struct {
    Num  uint8         // Number of segment-data fields in this data area. This is also the number of segments in this profile.
    Data []SegmentData `racf:"size=Num"` // Segment Data
}

type IndBlkEntry struct {
    Id            uint8            // Entry identifier: 0x21 - Normal index entry (non-duplicate entry); 0x22 - Duplicate index entry; 0x23 - Alias index entry.
    Type          uint8            // Type of profile for this index entry: 0x01 - Group; 0x02 - User; 0x04 - Data set; 0x05 - General resource
    LenEntry      uint16           // Length of this index entry
    Offset        uint16           // Offset from the beginning of the entry to the segment data area for regular index entries, and offset from the beginning of the entry to the base profile data area for alias index.
    CompressCount uint16           // Front-end compression count.
    LenName       uint16           // Length of index entry name
    _             []byte           `racf:"size=2"`       // Reserved
    Name          decode.EBCDICStr `racf:"size=LenName"` // Index entry name
    Data          SegmentDataL1Reg // Segment data area
}

func (e *IndBlkEntry) String() string {
    retVal := fmt.Sprintf("Id: 0x%02x (%s); Type: 0x%02x (%s); LenEntry: %d; Offset: %d; CompressCount: 0x%04x; NameLen:%d ;Name: %v; \n\tNumber of record: %d\n",
        e.Id, IndexEntryIDs[e.Id], e.Type, IndexEntryTypes[e.Type], e.LenEntry, e.Offset, e.CompressCount, e.LenName, &e.Name, e.Data.Num)
    for i, sd := range e.Data.Data {
        retVal += fmt.Sprintf("\t[%d] Id: 0x%02x (%s); RBA: %v\n", i, sd.Id, IndexEntrySegmentIDs[e.Type][sd.Id], &sd.RBA)
    }
    return retVal
}

func (e *IndBlkEntry) UnmarshalBinary(data []byte) error {
    t := reflect.TypeOf(*e)
    v := reflect.ValueOf(e).Elem()
    if len(data) < decode.Size(v) {
        return fmt.Errorf("IndBlkEntry.UnmarshalBinary: not enough data")
    }

    for i, ptr := 0, 0; i < t.NumField(); i++ {
        curT := t.Field(i)
        curV := v.Field(i)
        tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
        size, err := decode.DecodeValue(data[ptr:], &curV, tags)
        if err != nil {
            return fmt.Errorf("IndBlkEntry.UnmarshalBinary: %v", err)
        }
        ptr += size
    }
    return nil
}

type SequenceSetChain struct {
    Id  uint16         // 0x2066 Sequence Set Chain Pointer Entry Identifier
    RBA decode.Address `racf:"size=6"` // RBA of next level-1 index block (0 if last one of the set)
}

func (ssc *SequenceSetChain) String() string {
    return fmt.Sprintf("Sequence set chain pointer entry: %v", &ssc.RBA)
}

func (ssc *SequenceSetChain) UnmarshalBinary(data []byte) error {
    t := reflect.TypeOf(*ssc)
    v := reflect.ValueOf(ssc).Elem()
    if len(data) < decode.Size(v) {
        return fmt.Errorf("SequenceSetChain.UnmarshalBinary: not enough data")
    }

    for i, ptr := 0, 0; i < t.NumField(); i++ {
        curT := t.Field(i)
        curV := v.Field(i)
        tags, _ := decode.ParseTag(curT.Tag.Get("racf"), v)
        size, err := decode.DecodeValue(data[ptr:], &curV, tags)
        if err != nil {
            return fmt.Errorf("IndBlkEntry.UnmarshalBinary: %v", err)
        }
        ptr += size
    }
    return nil
}

type IndBlk struct {
    Hdr     IndBlkHdr        // Header
    Entries []IndBlkEntry    // Table of index entries.
    SSC     SequenceSetChain // Pointer to the next Index Block
}

func (ib *IndBlk) String() string {
    retVal := fmt.Sprintf("Header: %v\nEntries:\n", &ib.Hdr)
    for i, entry := range ib.Entries {
        retVal += fmt.Sprintf("[%d] %v", i, &entry)
    }
    retVal += fmt.Sprintf("Next: %v", &ib.SSC)
    return retVal
}

func (ib *IndBlk) UnmarshalBinary(data []byte) error {
    if err := ib.Hdr.UnmarshalBinary(data); err != nil {
        return err
    }

    ptr := decode.Size(reflect.ValueOf(ib.Hdr))
    ib.Entries = make([]IndBlkEntry, ib.Hdr.EntryNum)
    for i := 0; i < int(ib.Hdr.EntryNum); i++ {
        var entry IndBlkEntry
        if err := entry.UnmarshalBinary(data[ptr:]); err != nil { // 0x1000 is size of index block
            return err
        }
        //Uncompress Name
        if entry.CompressCount != 0 {
            var fullName decode.EBCDICStr
            fullName = append(fullName, ib.Entries[i-1].Name[:entry.CompressCount]...)
            entry.Name = append(fullName, entry.Name...)
        }
        ib.Entries[i] = entry
        ptr += int(entry.LenEntry)
    }
    if err := ib.SSC.UnmarshalBinary(data[ib.Hdr.OffsetLast:]); err != nil {
        return err
    }
    return nil
}
