package sections

import (
	"encoding/hex"
	"fmt"
	"reflect"

	"racfudit/common"
	"racfudit/decode"
)

type DEFNS struct {
	ICTMPL   uint16         // Template length
	ICTMPN   uint8          // Template number
	ICTMRSV1 uint8          // Align to half word boundary
	ICTMPRBA decode.Address `racf:"size=6"` // RBA of FDT
	ICTMRSV2 uint64         `racf:"size=6"` // Reserved
}

type PassSyntaxRules struct {
	ICBPSLEN byte    // Starting length value
	ICBPELEN byte    // Ending length value
	ICBPRULS [8]byte // Content rules
}

// https://www.ibm.com/docs/en/zos/2.4.0?topic=guide-inventory-control-block-icb
type ICB struct {
	ICBCHAIN int32          // Reserved
	ICBBAMNO int32          // Number of BAM blocks in data set
	ICCIBRBA decode.Address `racf:"size=6"`             // Relative byte addresses (RBA) of highest level CIB
	ICISSRBA decode.Address `racf:"size=6"`             // RBA of first block of index sequence set
	ICBAMRBA decode.Address `racf:"size=6"`             // RBA of first BAM
	ICBEXTND bool           `racf:"size=1,bit=0"`       // RACF data set has been extended
	ICBEDAT  bool           `racf:"size=1,bit=2"`       // RESIDENT data blocks option used on some system
	ICBDSFMT bool           `racf:"size=1,bit=3"`       // 1 = new RACF data set format
	ICBWIP   bool           `racf:"size=1,bit=4,final"` // HPCS 1 = Write In Progress
	ICTMPCNT int8           // Number of templates
	ICBAMHWM decode.Address `racf:"size=6"` // BAM HWM
	ICBTEMP  [9]DEFNS
	_        []byte             `racf:"size=16"`      // Reserved
	ICBNLS   bool               `racf:"size=1,bit=1"` // RACF data set has been extended
	ICBNDSS  bool               `racf:"size=1,bit=2"` // RESIDENT data blocks option used on some system
	ICBNTVS  bool               `racf:"size=1,bit=3"` // 1 = new RACF data set format
	ICBNDVS  bool               `racf:"size=1,bit=4"` // HPCS 1 = Write In Progress
	ICBNTMS  bool               `racf:"size=1,bit=5"` // No terminal statistics
	ICBNADS  bool               `racf:"size=1,bit=6"` // No ADSP protection
	ICBEGN   bool               `racf:"size=1,bit=7"` // EGN support in effect
	ICBEXTA  byte               // Reserved
	ICBTAPE  bool               `racf:"size=1,bit=0"` // Tape volume protection
	ICBDASD  bool               `racf:"size=1,bit=1"` // DASD volume protection
	ICBDGEN  bool               `racf:"size=1,bit=2"` // Generic profiles for data set class
	ICBDGCM  bool               `racf:"size=1,bit=3"` // Generic commands for data set class
	ICBRDSN  bool               `racf:"size=1,bit=4"` // Input data set name will be used for logging and messages
	ICBJXAL  bool               `racf:"size=1,bit=5"` // JES-XBMALLRACF is in effect
	ICBJCHK  bool               `racf:"size=1,bit=6"` // JES-EARLYVERIFY is in effect
	ICBJALL  bool               `racf:"size=1,bit=7"` // JES-BATCHALLRACF is in effect
	ICBAGRO  bool               `racf:"size=1,bit=1"` // Audit GROUP class
	ICBAUSE  bool               `racf:"size=1,bit=2"` // Audit USER class
	ICBADAT  bool               `racf:"size=1,bit=3"` // Audit DATASET class
	ICBADAS  bool               `racf:"size=1,bit=4"` // Audit DASDVOL class
	ICBATAP  bool               `racf:"size=1,bit=5"` // Audit TAPEVOL class
	ICBATER  bool               `racf:"size=1,bit=6"` // Audit TERMINAL class
	ICBAOPR  bool               `racf:"size=1,bit=7"` // Audit OPERATIONS attribute
	ICBAXTA  byte               // Reserved
	ICBTERP  bool               `racf:"size=1,bit=0"` // Terminal authorization checking
	ICBTUAC  bool               `racf:"size=1,bit=1"` // Default UACC for terminals not defined to RACF. If ON, UACC = NONE. If OFF, UACC = READ.
	ICBAVIO  bool               `racf:"size=1,bit=2"` // Do not create log record for command violations only
	ICBSAUD  bool               `racf:"size=1,bit=3"` // Do not audit SPECIAL users
	ICBMGDG  bool               `racf:"size=1,bit=4"` // MODEL-GDG in effect
	ICBMUSR  bool               `racf:"size=1,bit=5"` // MODEL-USER in effect
	ICBMGRP  bool               `racf:"size=1,bit=6"` // MODEL-GROUP in effect
	ICBLGRP  bool               `racf:"size=1,bit=7"` // LIST-OF-GRPS in effect
	ICBCHCT  [10]int32          // Change count array for all levels of index blocks
	ICBPINV  byte               // Global max password interval value, valid range 1-254
	ICBCSTA  uint32             // Class STATISTICS mask
	ICBCAUD  uint32             // Class AUDIT mask
	ICBCPRO  uint32             // Class PROTECTION mask
	ICBPHIST byte               // Password HISTORY value
	ICBPRVOK byte               // Password REVOKE value
	ICBPWARN byte               // Password WARNING value
	ICBPSYN  [8]PassSyntaxRules // Password SYNTAX rules
	ICBINACT byte               // INACTIVATE interval
	ICBCGEN  uint32             // Generic profile checking, class mask
	ICBCGCM  uint32             // Generic commands processing, class mask
	ICBFPDS  bool               `racf:"size=4,bit=0"`        // Fastpath for DATASET class
	ICBTDSN  bool               `racf:"size=4,bit=1"`        // Tape data set protection in effect
	ICBPRO   bool               `racf:"size=4,bit=8"`        // PROTECT-ALL is in effect
	ICBPROF  bool               `racf:"size=4,bit=9"`        // 1 - PROTECT-ALL WARNING is in effect, 0 - PROTECT-ALL FAILURE is in effect (This flag is ignored if ICBPRO has a value of '0'B)
	ICBEOS   bool               `racf:"size=4,bit=10"`       // ERASE-ON-SCRATCH is in effect
	ICBEOSL  bool               `racf:"size=4,bit=11"`       // ERASE-ON-SCRATCH by SECLEVEL is in effect (This flag is ignored if ICBEOS has a value of '0'B)
	ICBEOSA  bool               `racf:"size=4,bit=12"`       // ERASE-ON-SCRATCH for all data sets is in effect (This flag is ignored if ICBEOS has a value of '0' B)
	ICBPLC   bool               `racf:"size=4,bit=13"`       // Mixed case password
	ICBPSC   bool               `racf:"size=4,bit=14"`       // Special characters are allowed in passwords
	ICBPROG  bool               `racf:"size=4,bit=16,final"` // PROGRAM CONTROL is in effect
	ICBFPTH  uint32             // Class FASTPATH mask
	ICBSLVL  byte               // Security Level for ERASE-ON-SCRATCH
	ICBRETP  uint16             // Security Retention Period
	ICBQLLN  byte               // Length of prefix for single level data set names
	//ICBQUAL  [9]byte            // Installation controlled prefix for single level data set names, plus period for level
	ICBQUAL  decode.EBCDICStr `racf:"size=9"` // Installation controlled prefix for single level data set names, plus period for level
	ICBSLAU  byte             // SECLEVEL to audit
	ICBALIAS byte             // UNSIGNED 1 ICBALIAS application identity mapping byte
	ICBCHCTD uint32           // Change count for data blocks, used to maintain current in-storage blocks with a shared RACF data set
	ICBSWPW  [8]byte          // Password for RVARY SWITCH command
	ICBINPW  [8]byte          // Password for RVARY ACTIVE/INACTIVE command
	ICBLRCL  [16]byte         // CDT-ANCHORED RACLISTED profile class mask, ON if active
	ICBLGNL  [16]byte         // CDT-ANCHORED GENLISTED profile class mask, ON if active
	ICBLSTAC [16]byte         // Class STATISTICS option mask long version, ON if active
	ICBLAUDC [16]byte         // Class AUDITING option mask long version, ON if active
	ICBLPROC [16]byte         // Class PROTECTION option mask long version, ON if active
	ICBLGENC [16]byte         // Class mask for GENERIC PROFILE CHECKING long version, ON if active
	ICBLGCMC [16]byte         // Class mask for GENERIC COMMAND CHECKING long version, ON if active
	ICBLFPTC [16]byte         // Class FASTPATH option mask long version, ON if active
	ICBPMIN  int8             // SETROPTS PASSWORD(MINCHANGE) setting
	ICNTMPCT byte             // Number of new templates
	ICBTMPRL decode.EBCDICStr `racf:"size=8"` // Release level
	ICBTMPAL decode.EBCDICStr `racf:"size=8"` // APAR level
	ICBTXRBA decode.Address   `racf:"size=6"` // RBA of the template extensions
	ICBTXLN  int16            // Length of the template extension
	_        []byte           `racf:"size=136"` // Reserved
	ICBVMSSP uint32           // VM 370 SYNC counter
	ICBVMSXA uint32           // VMXA ACI SYNC counter
	ICBBMAPA decode.EBCDICStr `racf:"size=8"` // VM XA profile name which contains the audit settings
	ICBBMAPP decode.EBCDICStr `racf:"size=8"` // VM XA profile name contains the project settings
	ICBMAPSZ uint16           // Length of the entire ACI bit map with uncompressed events
	ICBDIAL  byte             // Indicator for: DIAL CMND
	ICBPRMSG byte             // Indicator for: DIAL CMND, PRELOGON MESSAGE CMD
	ICBEVENT [88]byte         // ACI bit map events
	ICBSINT  int16            // LU Session Interval
	ICBLGAL  [16]byte         // SETROPTS "LOGOPTIONS ALWAYS" class mask, ON if active
	ICBLNVR  [16]byte         // SETROPTS "LOGOPTIONS NEVER" class mask, ON if active
	ICBLGSU  [16]byte         // SETROPTS "LOGOPTIONS SUCCESSES" class mask, ON if active
	ICBLGFL  [16]byte         // SETROPTS "LOGOPTIONS FAILURES" class mask, ON if active
	ICBJSYS  decode.EBCDICStr `racf:"size=8"` // User ID from the SETROPTS command JES(NJEUSERID(id))
	ICBJUND  decode.EBCDICStr `racf:"size=8"` // User ID from the SETROPTS command JES(UNDEFINEDUSER(id))
	ICBRCGSN int32            // RACF group data synchronization value
	ICBDLGA  bool             `racf:"size=1,bit=0"`       // LOGOPTIONS "ALWAYS" for the DATASET class
	ICBDLGN  bool             `racf:"size=1,bit=1"`       // LOGOPTIONS "NEVER" FOR THE DATASET CLASS
	ICBDLGS  bool             `racf:"size=1,bit=2"`       // LOGOPTIONS "SUCCESSES" for the DATASET class
	ICBDLGF  bool             `racf:"size=1,bit=3,final"` // LOGOPTIONS "FAILURES" for the DATASET class
	ICBCMPM  bool             `racf:"size=1,bit=0"`       // SETROPTS COMPATMODE, ON if active
	ICBMLSF  bool             `racf:"size=1,bit=1"`       // SETROPTS MLS FAILURES/WARNING - FAILURES if "ON" - (1) - WARNING if "OFF" - (0)
	ICBMLAF  bool             `racf:"size=1,bit=2"`       // SETROPTS MLACTIVE FAILURES/WARNING - FAILURES if "ON" - (1) - WARNING if "OFF" - (0)
	ICBCATF  bool             `racf:"size=1,bit=3"`       // SETROPTS CATDSNS FAILURES/WARNING - FAILURES if "ON" - (1) - WARNING if "OFF" - (0)
	ICBAAPL  bool             `racf:"size=1,bit=4"`       // SETROPTS APPLAUDIT ON if active
	ICBNOADC bool             `racf:"size=1,bit=5,final"` // SETROPTS NOADDCREATOR - on if NOADDCREATOR in effect
	ICBSPAUD decode.EBCDICStr `racf:"size=8"`             // VM/SP profile names which contains the audit settings
	ICBSPCTL decode.EBCDICStr `racf:"size=8"`             // VM/SP profile names which contains the protect settings
	ICBSLCL  bool             `racf:"size=1,bit=0"`       // SETROPTS SECLABELCONTROL - ON if active
	ICBCATD  bool             `racf:"size=1,bit=1"`       // SETROPTS CATDSNS - ON if active
	ICBMLQT  bool             `racf:"size=1,bit=2"`       // SETROPTS MLQUIET - ON if active
	ICBMLST  bool             `racf:"size=1,bit=3"`       // SETROPTS MLSTABLE - ON if active
	ICBMLS   bool             `racf:"size=1,bit=4"`       // SETROPTS MLS - ON if active
	ICBMLAC  bool             `racf:"size=1,bit=5"`       // SETROPTS MLACTIVE - ON if active
	ICBGNOW  bool             `racf:"size=1,bit=6"`       // SETROPTS GENERICOWNER - ON if active
	ICBAUSL  bool             `racf:"size=1,bit=7"`       // SETROPTS SECLABELAUDIT - ON if active
	ICBNL1   decode.EBCDICStr `racf:"size=3"`             // PRIMARY LANGUAGE default
	ICBNL2   decode.EBCDICStr `racf:"size=3"`             // SECONDARY LANGUAGE default
	ICBSESS  bool             `racf:"size=1,bit=0,final"` // SESSIONINTERVAL dirty bit, 0=>Field not initialized, 1=>Field is initialized.
	ICBMLFS  bool             `racf:"size=1,bit=0"`       // Security labels required for File System Objects SETR MLFSOBJ
	ICBMLIP  bool             `racf:"size=1,bit=1"`       // Security labels required for IPC Objects SETR MLIPCOBJ
	ICBMLNM  bool             `racf:"size=1,bit=2"`       // Display of Names Restricted by Security label SETR MLNAMES
	ICBSBYS  bool             `racf:"size=1,bit=3,final"` // Security label by System requested SETR SECLBYSYSETM
	_        []byte           `racf:"size=85"`            // Reserved
	ICBALRBA uint64           `racf:"size=6"`             // Highest ALIAS index block
	ICBASRBA uint64           `racf:"size=6"`             // ALIAS index sequence set
	ICBSMCT  uint32           // Count field to control purge of VLF class IRRSMAP
	ICBKRBLV byte             // SETROPTS KERBLVL setting
	_        []byte           `racf:"size=1"` // Reserved
	ICBID    decode.EBCDICStr `racf:"size=8"` // Identifier, gets filled in during IRRMIN00 initialization
	ICBVRMN  decode.EBCDICStr `racf:"size=6"` // Version/release/modification number, also filled in IRRMIN00 (see https://www.rshconsulting.com/racfres.htm)
	// HRF7760 - V1 R11 - 09/30/12
	// HRF7770 - V1 R12 - 09/30/14
	// HRF7780 - V1 R13 - 09/30/16
	// HRF7790 - V2 R01 - 09/30/18
	// HRF77A0 - V2 R02 - 09/30/20
	// HRF77B0 - V2 R03 - 09/30/22
	// HRF77C0 - V2 R04
	// HRF77D0 - V2 R05
	ICTSEGLN int16            // Length of segment table
	ICTSEGRB uint64           `racf:"size=6"`             // RBA of segment table
	ICBINITF bool             `racf:"size=1,bit=0,final"` // ICB was completely initialized by RDS IRRMIN00
	_        []byte           `racf:"size=3"`             // Reserved
	ICBUSCT  uint32           // ACEE data repository change count for user profile
	ICBGPCT  uint32           // ACEE data repository change count for group profile
	ICBGRCT  uint32           // ACEE data repository change count for general resource classes APPL, APPCPORT, JESINPUT, CONSOLE, TERMINAL, GTERMINL & SECLABEL
	ICBUMCT  uint32           // count field to control purge of VLF class IRRUMAP
	ICBGMCT  uint32           // count field to control purge pf VLF class IRRGMAP
	ICBTMPLV decode.EBCDICStr `racf:"size=7"` // Template level value filled in by IRRMIN00.
	ICBVPROC [128]byte        // Class protection mask
	ICBVGENC [128]byte        // Generic profile checking class mask
	ICBVGCMC [128]byte        // Generic command processing class mask
	ICBVRCL  [128]byte        // CDT-anchored RACLISTed profile class mask
	ICBVGNL  [128]byte        // CDT-anchored GENLISTed profile class mask
	ICBVFPTC [128]byte        // Fastpath option class mask
	ICBVAUDC [128]byte        // Auditing option class mask
	ICBVSTAC [128]byte        // Statistics option mask
	ICBVLGA  [128]byte        // SETROPTS LOGOPTIONS ALWAYS class mask
	ICBVLNV  [128]byte        // SETROPTS LOGOPTIONS NEVER class mask
	ICBVLGS  [128]byte        // SETROPTS LOGOPTIONS SUCCESSES class mask
	ICBVLGF  [128]byte        // SETROPTS LOGOPTIONS FAILURES class mask
	ICTMPXCT uint8            // Number of template extensions
	ICBPREP  uint16           // Password algorithm repetition factor
	ICBPMEM  uint16           // Password algorithm memory factor
	ICBPALG  uint8            // Password algorithm in effect: 0 = DES or the algorithm as indicated by ICHDEX01 (masking, DES, or installation-defined) 1 = PBKDF2
}

func (icb *ICB) String() string {
	retVal := "Inventory Control Block\n"
	T := reflect.TypeOf(*icb)
	V := reflect.ValueOf(icb).Elem()
	offset := 0
	for i := 0; i < T.NumField(); i++ {
		fs := T.Field(i)
		tags, _ := decode.ParseTag(fs.Tag.Get("racf"), V)
		size := tags["size"]
		if size == 0 {
			size = decode.Size(V.Field(i))
		}

		if fs.Name == "_" {
			offset += size
			continue
		}

		fieldValue := V.Field(i).Interface()
		switch fieldValue := fieldValue.(type) {
		case decode.EBCDICStr:
			retVal += fmt.Sprintf("\t%s: %v (origin: %v; size: %d; offset: 0x%02x)\n", fs.Name, &fieldValue, hex.EncodeToString(fieldValue), size, offset)
		case decode.Address:
			retVal += fmt.Sprintf("\t%s: %v (size: %d; offset: 0x%02x)\n", fs.Name, &fieldValue, size, offset)
		case [9]DEFNS:
			retVal += fmt.Sprintf("\t%s (size: %d; offset: 0x%02x):\n", fs.Name, size, offset)
			for i, e := range fieldValue {
				retVal += fmt.Sprintf("\t\t[%d] Template length: %v:\n", i, e.ICTMPL)
				retVal += fmt.Sprintf("\t\t[%d] Template number: %v:\n", i, e.ICTMPN)
				retVal += fmt.Sprintf("\t\t[%d] Alignment: %v:\n", i, e.ICTMRSV1)
				retVal += fmt.Sprintf("\t\t[%d] RBA: %v:\n", i, &e.ICTMPRBA)
			}
		default:
			retVal += fmt.Sprintf("\t%s: %v (size: %d; offset: 0x%02x)\n", fs.Name, fieldValue, size, offset)
		}

		// Move offset if the field isn't a flag or last bit of a flag
		if _, ok := tags["final"]; fs.Type.Kind() != reflect.Bool || ok || tags["bit"] == (8*size-1) {
			offset += size
		}
	}
	return retVal
}

func (icb *ICB) UnmarshalBinary(data []byte) error {
	t := reflect.TypeOf(*icb)
	v := reflect.ValueOf(icb).Elem()
	if len(data) < decode.Size(v) {
		return fmt.Errorf("ICB.UnmarshalBinary: not enough data")
	}

	for i, ptr := 0, 0; i < t.NumField(); i++ {
		curT := t.Field(i)
		curV := v.Field(i)
		common.Log.Debug("Extracting ICB field %s (%v) at offset 0x%08x", curT.Name, curT.Type, ptr)

		tags, err := decode.ParseTag(curT.Tag.Get("racf"), v)
		if err != nil {
			return fmt.Errorf("ICB.UnmarshalBinary: %v", err)
		}
		size, err := decode.DecodeValue(data[ptr:], &curV, tags)
		if err != nil {
			return fmt.Errorf("ICB.UnmarshalBinary: %v", err)
		}
		ptr += size
	}
	return nil
}

func ExtractICB(data []byte) (*ICB, error) {
	var icb ICB
	if err := icb.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("error extracting ICB: %v", err)
	}
	return &icb, nil
}
