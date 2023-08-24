package decode

import (
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "unicode"
)

// RACF Types: https://www.ibm.com/docs/en/zos/2.1.0?topic=templates-format-field-definitions
const (
    T_INT  = iota + 1 // uint8, uint16, uint32, uint64
    T_СHAR            // EBCDICStr - used for any binary data (printable and non-printable)
    T_DATE            // Date - 3-byte and 4 byte date
    T_TIME            // Time
    T_BIN             // HexStr (may be needed to union with T_СHAR)
    T_FLAG            // Flag (rename into T_BIN???)
)

var e2a = [256]byte{
    0, 1, 2, 3, 156, 9, 134, 127, 151, 141, 142, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 157, 133, 8, 135, 24, 25, 146, 143, 28, 29, 30, 31,
    128, 129, 130, 131, 132, 10, 23, 27, 136, 137, 138, 139, 140, 5, 6, 7,
    144, 145, 22, 147, 148, 149, 150, 4, 152, 153, 154, 155, 20, 21, 158, 26,
    32, 160, 161, 162, 163, 164, 165, 166, 167, 168, 91, 46, 60, 40, 43, 33,
    38, 169, 170, 171, 172, 173, 174, 175, 176, 177, 93, 36, 42, 41, 59, 94,
    45, 47, 178, 179, 180, 181, 182, 183, 184, 185, 124, 44, 37, 95, 62, 63,
    186, 187, 188, 189, 190, 191, 192, 193, 194, 96, 58, 35, 64, 39, 61, 34,
    195, 97, 98, 99, 100, 101, 102, 103, 104, 105, 196, 197, 198, 199, 200, 201,
    202, 106, 107, 108, 109, 110, 111, 112, 113, 114, 203, 204, 205, 206, 207, 208,
    209, 126, 115, 116, 117, 118, 119, 120, 121, 122, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
    123, 65, 66, 67, 68, 69, 70, 71, 72, 73, 232, 233, 234, 235, 236, 237,
    125, 74, 75, 76, 77, 78, 79, 80, 81, 82, 238, 239, 240, 241, 242, 243,
    92, 159, 83, 84, 85, 86, 87, 88, 89, 90, 244, 245, 246, 247, 248, 249,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 250, 251, 252, 253, 254, 255,
}

func ebcdic2ascii(data []byte) []byte {
    retVal := make([]byte, len(data))
    for i, b := range data {
        retVal[i] = e2a[b]
    }
    return retVal
}

type EBCDICStr []byte

func (s *EBCDICStr) String() string {
    return string(ebcdic2ascii(*s))
}

func (s *EBCDICStr) Hex() string {
    return hex.EncodeToString(*s)
}

// Check if a string EBCDICStr only printable characters
func (s *EBCDICStr) IsPrint() bool {
    for _, c := range s.String() {
        if !unicode.IsPrint(c) {
            return false
        }
    }
    return true
}

type Address uint64

func (a *Address) String() string {
    return fmt.Sprintf("0x%08x", *a)
}

type HexStr []byte

func (s *HexStr) String() string {
    return hex.EncodeToString(*s)
}

type Date []byte

func (d *Date) String() string {
    switch len(*d) {
    case 3:
        return d.to3Human()
    case 4:
        return d.to4Human()
    }
    return ""
}

func (d *Date) to3Human() string {
    retFmt := "%d, day %d"
    year := int(d.index(0))
    day := int(binary.BigEndian.Uint16([]byte(*d)[1:])) >> 4
    sign := int(d.index(2)) & 0xf

    // Handle zero date ('FFFFFF', '00000D', '00000C', '000000' )
    if (year == 0 && day == 0) || (year == 0xff && day == 0xfff && sign == 0xf) {
        return fmt.Sprintf(retFmt, 1970, 1)
    }
    year = year&0xf + 10*(year>>4)
    if year > 70 {
        year += 1900
    } else {
        year += 2000
    }
    day = day&0xf + 10*((day>>4)&0xf) + 100*(day>>8)
    return fmt.Sprintf(retFmt, year, day)
}

func (d *Date) to4Human() string {
    // Handle zero date ('FFFFFFFF', '0000000D', '0000000C', '00000000')
    if (d.index(0) == 0xff && d.index(1) == 0xff && d.index(2) == 0xff && d.index(3) == 0xff) ||
        (d.index(0) == 0 && d.index(1) == 0 && d.index(2) == 0 &&
            (d.index(3) == 0 || d.index(3) == 0x0c || d.index(3) == 0x0d || d.index(3) == 0x0d)) {
        return "1970.01.01"
    }
    return fmt.Sprintf("%02x%02x.%02x.%02x", d.index(0), d.index(1), d.index(2), d.index(3))
}

func (d *Date) Hex() string {
    return hex.EncodeToString(*d)
}

func (d *Date) index(i int) uint8 {
    return []byte(*d)[i]
}

type Time [4]byte

func (t *Time) String() string {
    return fmt.Sprintf("%02x:%02x:%02x (%02x ms)", t[0], t[1], t[2], t[3])
}

func (t *Time) Hex() string {
    return hex.EncodeToString((*t)[:])
}

type Flag []byte

func (f *Flag) String() string {
    var retVal string
    if len(*f) == 0 {
        retVal = ""
    } else {
        for _, b := range *f {
            retVal += fmt.Sprintf("%08b", b)
        }
    }
    return retVal
}

func (f *Flag) Hex() string {
    return hex.EncodeToString(*f)
}

// While NOT USED. May be used in template.go for Flag1 and Flag2 (in functions IsRepeatGroup, etc)
func (f *Flag) IsSet(i int) bool {
    byteNum := i / 8
    if len(*f) < byteNum+1 {
        return false
    }
    bitNum := i % 8
    if (([]byte(*f)[byteNum] >> (7 - bitNum)) & 1) == 1 {
        return true
    }
    return false
}

// Template field types aren't pointed in template fields.
// Therefore, it is not possible to accurately determine the field type
// based only on information from its description like Flag1, Flag2 and Length.
// To solve that all publicly available information about template field types
// has been statically added into the code.
// For each profile (GROUP, USER, CONNECT, DATASET, GENERAL) an map has been created containing the names of the template fields
// with their types.
//
// if the field is not included in any of the slices, then a probabilistic approach
// is applied to determine the field type (function GetFieldTypeWithoutFieldDB).
//
// Template field types are presented according to z/OS 2.4.0 documentation (without combination fields)
var FieldTypes map[string]map[string]int = map[string]map[string]int{
    "GROUP":   fieldTypesGroup,
    "USER":    fieldTypesUser,
    "CONNECT": fieldTypesConnect,
    "DATASET": fieldTypesDataset,
    "GENERAL": fieldTypesGeneral,
}

// Group template fields: https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-group-template-racf-database
var fieldTypesGroup map[string]int = map[string]int{
    "ENTYPE":   T_INT,
    "VERSION":  T_INT,
    "SUPGROUP": T_СHAR,
    "AUTHDATE": T_DATE,
    "AUTHOR":   T_СHAR,
    "INITCNT":  T_INT,
    "UACC":     T_FLAG,
    "NOTRMUAC": T_FLAG,
    "INSTDATA": T_СHAR,
    "MODELNAM": T_СHAR,
    "FLDCNT":   T_INT,
    "FLDNAME":  T_СHAR,
    "FLDVALUE": T_BIN,
    "FLDFLAG":  T_FLAG,
    "SUBGRPCT": T_INT,
    "SUBGRPNM": T_СHAR,
    "ACLCNT":   T_INT,
    "USERID":   T_СHAR,
    "USERACS":  T_FLAG,
    "USRCNT":   T_INT,
    "USRNM":    T_СHAR,
    "USRDATA":  T_BIN,
    "USRFLG":   T_FLAG,
    "UNVFLG":   T_BIN,
    "DATAAPPL": T_СHAR,
    "DATACLAS": T_СHAR,
    "MGMTCLAS": T_СHAR,
    "STORCLAS": T_СHAR,
    "GID":      T_INT,
    "ROLEN":    T_INT,
    "ROLES":    T_СHAR,
    "CSCNT":    T_INT,
    "CSTYPE":   T_FLAG,
    "CSKEY":    T_СHAR,
    "CSVALUE":  T_СHAR,
}

// User template fields: https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-user-template-racf-database
var fieldTypesUser map[string]int = map[string]int{
    "ENTYPE":   T_INT,
    "VERSION":  T_INT,
    "AUTHDATE": T_DATE,
    "AUTHOR":   T_СHAR,
    "FLAG1":    T_FLAG,
    "FLAG2":    T_FLAG,
    "FLAG3":    T_FLAG,
    "FLAG4":    T_FLAG,
    "FLAG5":    T_FLAG,
    "PASSINT":  T_INT,
    "PASSWORD": T_BIN,
    "PASSDATE": T_DATE,
    "PGMRNAME": T_СHAR,
    "DFLTGRP":  T_СHAR,
    "LJTIME":   T_TIME,
    "LJDATE":   T_DATE,
    "INSTDATA": T_СHAR,
    "UAUDIT":   T_FLAG,
    "FLAG6":    T_FLAG,
    "FLAG7":    T_FLAG,
    "FLAG8":    T_FLAG,
    "MAGSTRIP": T_BIN,
    "PWDGEN":   T_INT,
    "PWDCNT":   T_INT,
    "OLDPWDNM": T_INT,
    "OLDPWD":   T_СHAR,
    "REVOKECT": T_INT,
    "MODELNAM": T_СHAR,
    "SECLEVEL": T_INT,
    "NUMCTGY":  T_INT,
    "CATEGORY": T_INT,
    "REVOKEDT": T_DATE,
    "RESUMEDT": T_DATE,
    "LOGDAYS":  T_FLAG,
    "LOGTIME":  T_TIME,
    "FLDCNT":   T_INT,
    "FLDNAME":  T_СHAR,
    "FLDVALUE": T_BIN,
    "FLDFLAG":  T_FLAG,
    "CLCNT":    T_INT,
    "CLNAME":   T_СHAR,
    "CONGRPCT": T_INT,
    "CONGRPNM": T_СHAR,
    "USRCNT":   T_INT,
    "USRNM":    T_СHAR,
    "USRDATA":  T_BIN,
    "USRFLG":   T_FLAG,
    "SECLABEL": T_СHAR,
    "CGGRPCT":  T_INT,
    "CGGRPNM":  T_СHAR,
    "CGAUTHDA": T_DATE,
    "CGAUTHOR": T_СHAR,
    "CGLJTIME": T_TIME,
    "CGLJDATE": T_DATE,
    "CGUACC":   T_BIN,
    "CGINITCT": T_INT,
    "CGFLAG1":  T_FLAG,
    "CGFLAG2":  T_FLAG,
    "CGFLAG3":  T_FLAG,
    "CGFLAG4":  T_FLAG,
    "CGFLAG5":  T_FLAG,
    "CGNOTUAC": T_FLAG,
    "CGGRPAUD": T_FLAG,
    "CGREVKDT": T_DATE,
    "CGRESMDT": T_DATE,
    "TUCNT":    T_INT,
    "TUKEY":    T_СHAR,
    "TUDATA":   T_BIN,
    "CERTCT":   T_INT,
    "CERTNAME": T_СHAR,
    "CERTLABL": T_СHAR,
    "CERTSJDN": T_СHAR,
    "CERTPUBK": T_BIN,
    "CERTRSV3": T_BIN,
    "FLAG9":    T_FLAG,
    "NMAPCT":   T_INT,
    "NMAPLABL": T_СHAR,
    "NMAPNAME": T_СHAR,
    "NMAPRSV1": T_СHAR,
    "NMAPRSV2": T_СHAR,
    "NMAPRSV3": T_СHAR,
    "NMAPRSV4": T_СHAR,
    "NMAPRSV5": T_СHAR,
    "PWDENV":   T_BIN,
    "PASSASIS": T_FLAG,
    "PHRASE":   T_BIN,
    "PHRDATE":  T_DATE,
    "PHRGEN":   T_INT,
    "PHRCNT":   T_INT,
    "OLDPHRNM": T_INT,
    "OLDPHR":   T_BIN,
    "CERTSEQN": T_INT,
    "PPHENV":   T_BIN,
    "DMAPCT":   T_INT,
    "DMAPLABL": T_СHAR,
    "DMAPNAME": T_СHAR,
    "DMAPRSV1": T_СHAR,
    "DMAPRSV2": T_СHAR,
    "PWDX":     T_BIN,
    "OPWDXCT":  T_INT,
    "OPWDXGEN": T_INT,
    "OPWDX":    T_BIN,
    "PHRASEX":  T_BIN,
    "PHRCNTX":  T_INT,
    "OLDPHRNX": T_INT,
    "OLDPHRX":  T_BIN,
    "FLAGROA":  T_FLAG,
    "MFAFLBK":  T_BIN,
    "FACTORN":  T_INT,
    "FACTOR":   T_СHAR,
    "FACACDT":  T_СHAR,
    "FACTAGS":  T_BIN,
    "MFAPOLN":  T_INT,
    "MFAPOLNM": T_СHAR,
    "DATAAPPL": T_СHAR,
    "DATACLAS": T_СHAR,
    "MGMTCLAS": T_СHAR,
    "STORCLAS": T_СHAR,
    "TACCNT":   T_СHAR,
    "TCOMMAND": T_СHAR,
    "TDEST":    T_СHAR,
    "THCLASS":  T_СHAR,
    "TJCLASS":  T_СHAR,
    "TLPROC":   T_СHAR,
    "TLSIZE":   T_INT,
    "TMCLASS":  T_СHAR,
    "TMSIZE":   T_INT,
    "TOPTION":  T_BIN,
    "TPERFORM": T_INT,
    "TRBA":     T_BIN,
    "TSCLASS":  T_СHAR,
    //"TUDATA": T_BIN,
    "TUNIT":    T_СHAR,
    "TUPT":     T_BIN,
    "TSOSLABL": T_СHAR,
    "TCONS":    T_СHAR,
    "OPIDENT":  T_СHAR,
    "OPCLASSN": T_INT,
    "OPCLASS":  T_INT,
    "OPPRTY":   T_INT,
    "XRFSOFF":  T_FLAG,
    "TIMEOUT":  T_BIN,
    "RSLKEYN":  T_INT,
    "RSLKEY":   T_INT,
    "TSLKEYN":  T_INT,
    "TSLKEY":   T_INT,
    "USERNL1":  T_СHAR,
    "USERNL2":  T_СHAR,
    "OPERSTOR": T_BIN,
    "OPERAUTH": T_FLAG,
    "OPERMFRM": T_FLAG,
    "OPERLEVL": T_FLAG,
    "OPERMON":  T_FLAG,
    "OPERROUT": T_FLAG,
    "OPERLOGC": T_FLAG,
    "OPERMGID": T_FLAG,
    "OPERDOM":  T_FLAG,
    "OPERKEY":  T_BIN,
    "OPERCMDS": T_BIN,
    "OPERUD":   T_FLAG,
    "OPERMCNT": T_INT,
    "OPERMSCP": T_СHAR,
    "OPERALTG": T_FLAG,
    "OPERAUTO": T_FLAG,
    "OPERHC":   T_FLAG,
    "OPERINT":  T_FLAG,
    "OPERUNKN": T_FLAG,
    "WANAME":   T_СHAR,
    "WABLDG":   T_СHAR,
    "WADEPT":   T_СHAR,
    "WAROOM":   T_СHAR,
    "WAADDR1":  T_СHAR,
    "WAADDR2":  T_СHAR,
    "WAADDR3":  T_СHAR,
    "WAADDR4":  T_СHAR,
    "WAACCNT":  T_СHAR,
    "WAEMAIL":  T_СHAR,
    "UID":      T_INT,
    "HOME":     T_СHAR,
    "PROGRAM":  T_СHAR,
    "CPUTIME":  T_INT,
    "ASSIZE":   T_INT,
    "FILEPROC": T_INT,
    "PROCUSER": T_INT,
    "THREADS":  T_INT,
    "MMAPAREA": T_INT,
    "MEMLIMIT": T_СHAR,
    "SHMEMMAX": T_СHAR,
    "IC":       T_СHAR,
    "CONSNAME": T_СHAR,
    "CTL":      T_FLAG,
    "MSGRECVR": T_FLAG,
    //"OPCLASSN": T_INT,
    //"OPCLASS": T_INT,
    "DOMAINSN": T_INT,
    "DOMAINS":  T_СHAR,
    "NGMFADMN": T_FLAG,
    "NGMFVSPN": T_BIN,
    "UUID":     T_СHAR,
    "DCENAME":  T_СHAR,
    "HOMECELL": T_СHAR,
    "HOMEUUID": T_СHAR,
    "DCEFLAGS": T_FLAG,
    "DPASSWDS": T_СHAR,
    "DCEENCRY": T_BIN,
    "FSROOT":   T_СHAR,
    "SNAME":    T_СHAR,
    "UNAME":    T_СHAR,
    "KERBNAME": T_СHAR,
    "MINTKTLF": T_СHAR,
    "MAXTKTLF": T_СHAR,
    "DEFTKTLF": T_СHAR,
    "SALT":     T_СHAR,
    "ENCTYPE":  T_СHAR,
    "CURKEYV":  T_СHAR,
    "CURKEY":   T_СHAR,
    "PREVKEYV": T_СHAR,
    "PREVKEY":  T_СHAR,
    "ENCRYPT":  T_BIN,
    "KEYFROM":  T_СHAR,
    "LDAPHOST": T_СHAR,
    "BINDDN":   T_СHAR,
    "BINDPW":   T_СHAR,
    "BINDPWKY": T_СHAR,
    "LDAPPROF": T_СHAR,
    "CSCNT":    T_INT,
    "CSTYPE":   T_FLAG,
    "CSKEY":    T_СHAR,
    "CSVALUE":  T_СHAR,
}

// Connect template fields: https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-connect-template-racf-database
var fieldTypesConnect map[string]int = map[string]int{
    "ENTYPE":   T_INT,
    "VERSION":  T_INT,
    "AUTHDATE": T_DATE,
    "AUTHOR":   T_СHAR,
    "LJTIME":   T_TIME,
    "LJDATE":   T_DATE,
    "UACC":     T_FLAG,
    "INITCNT":  T_INT,
    "FLAG1":    T_FLAG,
    "FLAG2":    T_FLAG,
    "FLAG3":    T_FLAG,
    "FLAG4":    T_FLAG,
    "FLAG5":    T_FLAG,
    "NOTRMUAC": T_BIN,
    "GRPAUDIT": T_BIN,
    "REVOKEDT": T_DATE,
    "RESUMEDT": T_DATE,
}

// Dataset template fields: https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-data-set-template-racf-database
var fieldTypesDataset map[string]int = map[string]int{
    "ENTYPE":   T_INT,
    "VERSION":  T_INT,
    "CREADATE": T_DATE,
    "AUTHOR":   T_СHAR,
    "LREFDAT":  T_DATE,
    "LCHGDAT":  T_DATE,
    "ACSALTR":  T_INT,
    "ACSCNTL":  T_INT,
    "ACSUPDT":  T_INT,
    "ACSREAD":  T_INT,
    "UNIVACS":  T_FLAG,
    "FLAG1":    T_FLAG,
    "AUDIT":    T_FLAG,
    "GROUPNM":  T_СHAR,
    "DSTYPE":   T_FLAG,
    "LEVEL":    T_INT,
    "DEVTYP":   T_BIN,
    "DEVTYPX":  T_СHAR,
    "GAUDIT":   T_FLAG,
    "INSTDATA": T_СHAR,
    "GAUDITQF": T_FLAG,
    "AUDITQS":  T_BIN,
    "AUDITQF":  T_BIN,
    "GAUDITQS": T_BIN,
    "WARNING":  T_FLAG,
    "SECLEVEL": T_INT,
    "NUMCTGY":  T_INT,
    "CATEGORY": T_BIN,
    "NOTIFY":   T_СHAR,
    "RETPD":    T_INT,
    "ACL2CNT":  T_INT,
    "PROGRAM":  T_СHAR,
    "USER2ACS": T_СHAR,
    "PROGACS":  T_BIN,
    "PACSCNT":  T_INT,
    "ACL2VAR":  T_СHAR,
    "FLDCNT":   T_INT,
    "FLDNAME":  T_СHAR,
    "FLDVALUE": T_BIN,
    "FLDFLAG":  T_FLAG,
    "VOLCNT":   T_INT,
    "VOLSER":   T_СHAR,
    "ACLCNT":   T_INT,
    "USERID":   T_СHAR,
    "USERACS":  T_FLAG,
    "ACSCNT":   T_INT,
    "USRCNT":   T_INT,
    "USRNM":    T_СHAR,
    "USRDATA":  T_BIN,
    "USRFLG":   T_FLAG,
    "SECLABEL": T_СHAR,
    "RESOWNER": T_СHAR,
    "DATAKEY":  T_СHAR,
    "ROLEN":    T_INT,
    "ROLES":    T_СHAR,
    "CSCNT":    T_INT,
    "CSTYPE":   T_FLAG,
    "CSKEY":    T_СHAR,
    "CSVALUE":  T_СHAR,
}

// General template fields: https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-general-template-racf-database
var fieldTypesGeneral map[string]int = map[string]int{
    "ENTYPE":   T_INT,
    "VERSION":  T_INT,
    "CLASTYPE": T_INT,
    "DEFDATE":  T_DATE,
    "OWNER":    T_СHAR,
    "LREFDAT":  T_DATE,
    "LCHGDAT":  T_DATE,
    "ACSALTR":  T_INT,
    "ACSCNTL":  T_INT,
    "ACSUPDT":  T_INT,
    "ACSREAD":  T_INT,
    "UACC":     T_FLAG,
    "AUDIT":    T_FLAG,
    "LEVEL":    T_INT,
    "GAUDIT":   T_FLAG,
    "INSTDATA": T_СHAR,
    "GAUDITQF": T_FLAG,
    "AUDITQS":  T_FLAG,
    "AUDITQF":  T_FLAG,
    "GAUDITQS": T_FLAG,
    "WARNING":  T_FLAG,
    "RESFLG":   T_FLAG,
    "TVTOCCNT": T_INT,
    "TVTOCSEQ": T_INT,
    "TVTOCCRD": T_DATE,
    "TVTOCIND": T_FLAG,
    "TVTOCDSN": T_СHAR,
    "TVTOCVOL": T_СHAR,
    "TVTOCRDS": T_СHAR,
    "NOTIFY":   T_СHAR,
    "LOGDAYS":  T_FLAG,
    "LOGTIME":  T_TIME,
    "LOGZONE":  T_BIN,
    "NUMCTGY":  T_INT,
    "CATEGORY": T_INT,
    "SECLEVEL": T_INT,
    "FLDCNT":   T_INT,
    "FLDNAME":  T_СHAR,
    "FLDVALUE": T_BIN,
    "FLDFLAG":  T_FLAG,
    "APPLDATA": T_СHAR,
    "MEMCNT":   T_INT,
    "MEMLST":   T_BIN,
    "VOLCNT":   T_INT,
    "VOLSER":   T_СHAR,
    "ACLCNT":   T_INT,
    "USERID":   T_СHAR,
    "USERACS":  T_FLAG,
    "ACSCNT":   T_INT,
    "USRCNT":   T_INT,
    "USRNM":    T_СHAR,
    "USRDATA":  T_BIN,
    "USRFLG":   T_FLAG,
    "SECLABEL": T_СHAR,
    "ACL2CNT":  T_INT,
    "ACL2NAME": T_СHAR,
    "ACL2UID":  T_СHAR,
    "ACL2ACC":  T_BIN,
    "ACL2ACNT": T_INT,
    "ACL2RSVD": T_BIN,
    "RACLHDR":  T_СHAR,
    "RACLDSP":  T_СHAR,
    "FILTERCT": T_INT,
    "FLTRLABL": T_СHAR,
    "FLTRSTAT": T_FLAG,
    "FLTRUSER": T_СHAR,
    "FLTRNAME": T_СHAR,
    "FLTRSVD1": T_BIN,
    "FLTRSVD2": T_BIN,
    "FLTRSVD3": T_BIN,
    "FLTRSVD4": T_BIN,
    "FLTRSVD5": T_BIN,
    "RACDHDR":  T_BIN,
    "DIDCT":    T_INT,
    "DIDLABL":  T_СHAR,
    "DIDUSER":  T_СHAR,
    "DIDRNAME": T_СHAR,
    "DIDRSVD1": T_BIN,
    "DIDRSVD2": T_BIN,
    "SESSKEY":  T_BIN,
    "SLSFLAGS": T_FLAG,
    "KEYDATE":  T_DATE,
    "KEYINTVL": T_INT,
    "SLSFAIL":  T_INT,
    "MAXFAIL":  T_INT,
    "SENTCNT":  T_INT,
    "SENTITY":  T_СHAR,
    "SENTFLCT": T_INT,
    "CONVSEC":  T_FLAG,
    "RETAIN":   T_FLAG,
    "JOBNMCNT": T_INT,
    "JOBNAMES": T_СHAR,
    "SSKEY":    T_BIN,
    "PTKEYLAB": T_СHAR,
    "PTTYPE":   T_СHAR,
    "PTTIMEO":  T_INT,
    "PTREPLAY": T_BIN,
    "STUSER":   T_СHAR,
    "STGROUP":  T_СHAR,
    "FLAGTRUS": T_FLAG,
    "FLAGPRIV": T_FLAG,
    "FLAGTRAC": T_FLAG,
    "SCRIPTN":  T_СHAR,
    "PARMN":    T_СHAR,
    "CERT":     T_BIN,
    "CERTPRVK": T_BIN,
    "RINGCT":   T_INT,
    "RINGNAME": T_СHAR,
    "CERTSTRT": T_СHAR,
    "CERTEND":  T_СHAR,
    "CERTCT":   T_INT,
    "CERTNAME": T_СHAR,
    "CERTUSAG": T_BIN,
    "CERTDFLT": T_FLAG,
    "CERTSJDN": T_BIN,
    "CERTLABL": T_СHAR,
    "CERTRSV1": T_СHAR,
    "CERTRSV2": T_СHAR,
    "CERTRSV3": T_СHAR,
    "CERTRSV4": T_СHAR,
    "CERTRSV5": T_СHAR,
    "CERTRSV6": T_СHAR,
    "CERTRSV7": T_СHAR,
    "CERTRSV8": T_СHAR,
    "CERTRSV9": T_СHAR,
    "CERTRSVA": T_СHAR,
    "CERTRSVB": T_СHAR,
    "CERTRSVC": T_СHAR,
    "CERTRSVD": T_СHAR,
    "CERTRSVE": T_СHAR,
    "CERTRSVF": T_СHAR,
    "CERTRSVG": T_СHAR,
    "CERTRSVH": T_СHAR,
    "CERTRSVI": T_СHAR,
    "CERTRSVJ": T_СHAR,
    "CERTRSVK": T_СHAR,
    "CERTPRVT": T_BIN,
    "CERTPRVS": T_INT,
    "CERTLSER": T_BIN,
    "RINGSEQN": T_INT,
    "CERTGREQ": T_BIN,
    "PARENT":   T_СHAR,
    "CHILDN":   T_INT,
    "CHILDREN": T_СHAR,
    "RESN":     T_INT,
    "RESOURCE": T_СHAR,
    "GROUPN":   T_INT,
    "GROUPS":   T_СHAR,
    "ROLEN":    T_INT,
    "ROLES":    T_СHAR,
    "KERBNAME": T_СHAR,
    "MINTKTLF": T_СHAR,
    "MAXTKTLF": T_СHAR,
    "DEFTKTLF": T_СHAR,
    "SALT":     T_СHAR,
    "ENCTYPE":  T_СHAR,
    "CURKEYV":  T_СHAR,
    "CURKEY":   T_СHAR,
    "PREVKEYV": T_СHAR,
    "PREVKEY":  T_СHAR,
    "ENCRYPT":  T_СHAR,
    "CHKADDRS": T_СHAR,
    "LDAPHOST": T_СHAR,
    "BINDDN":   T_СHAR,
    "BINDPW":   T_СHAR,
    "BINDPWKY": T_СHAR,
    "DOMAINDN": T_СHAR,
    "OPTIONS":  T_СHAR,
    "LOCALREG": T_СHAR,
    "KERBREG":  T_СHAR,
    "X509REG":  T_СHAR,
    "IPLOOK":   T_СHAR,
    "CDTPOSIT": T_INT,
    "CDTMAXLN": T_INT,
    "CDTMAXLX": T_INT,
    "CDTDFTRC": T_INT,
    "CDTKEYQL": T_INT,
    "CDTGROUP": T_СHAR,
    "CDTMEMBR": T_СHAR,
    "CDTFIRST": T_FLAG,
    "CDTOTHER": T_FLAG,
    "CDTOPER":  T_FLAG,
    "CDTUACC":  T_FLAG,
    "CDTRACL":  T_FLAG,
    "CDTGENL":  T_FLAG,
    "CDTPRFAL": T_FLAG,
    "CDTSLREQ": T_FLAG,
    "CDTMAC":   T_FLAG,
    "CDTSIGL":  T_FLAG,
    "CDTCASE":  T_FLAG,
    "CDTGEN":   T_FLAG,
    "USEMAP":   T_FLAG,
    "DOMAP":    T_FLAG,
    "MAPREQ":   T_FLAG,
    "MAPTIMEO": T_INT,
    "CFDTYPE":  T_FLAG,
    "CFMXLEN":  T_INT,
    "CFMXVAL":  T_INT,
    "CFMNVAL":  T_INT,
    "CFFIRST":  T_FLAG,
    "CFOTHER":  T_FLAG,
    "CFMIXED":  T_FLAG,
    "CFHELP":   T_СHAR,
    "CFLIST":   T_СHAR,
    "CFVALRX":  T_СHAR,
    "SIGREQD":  T_FLAG,
    "FAILLOAD": T_FLAG,
    "SIGAUDIT": T_FLAG,
    "CSFSEXP":  T_FLAG,
    "CSFSKLCT": T_INT,
    "CSFSKLBS": T_СHAR,
    "CSFSCLCT": T_INT,
    "CSFSCLBS": T_СHAR,
    "CSFAUSE":  T_FLAG,
    "CSFSCPW":  T_FLAG,
    "CSFSCPR":  T_FLAG,
    "MFDATA":   T_СHAR,
    "MFFCTRN":  T_INT,
    "MFFCTRS":  T_СHAR,
    "MFTIMEO":  T_INT,
    "MFREUSE":  T_BIN,
    "CSCNT":    T_INT,
    "CSTYPE":   T_FLAG,
    "CSKEY":    T_СHAR,
    "CSVALUE":  T_СHAR,
    "IDTTOKN":  T_СHAR,
    "IDTSEQN":  T_СHAR,
    "IDTCAT":   T_СHAR,
    "IDTSALG":  T_СHAR,
    "IDTTIMEO": T_INT,
    "IDTANYAP": T_СHAR,
}
