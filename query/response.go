package query

import (
	"fmt"

	"pgtoll/utils"
)

// RowDescription represents a column description in a query result
type RowDescription struct {
	FieldName             string `json:"fieldName"`
	ColumnObjectID        int32  `json:"columnObjectId"`
	ColumnAttributeNumber int16  `json:"columnAttributeNumber"`
	FieldDataTypeObjectID int32  `json:"fieldDataTypeObjectId"`
	DataTypeSize          int16  `json:"dataTypeSize"`
	TypeModifier          int32  `json:"typeModifier"`
	FieldFormatCode       int16  `json:"fieldFormatCode"`
}

// String returns a formatted string representation of the RowDescription
func (r RowDescription) String() string {
	return fmt.Sprintf(
		"FieldName=%s, ColumnObjectID=%d, ColumnAttributeNumber=%d, FieldDataTypeObjectID=%d, DataTypeSize=%d, TypeModifier=%d, FieldFormatCode=%d",
		r.FieldName,
		r.ColumnObjectID,
		r.ColumnAttributeNumber,
		r.FieldDataTypeObjectID,
		r.DataTypeSize,
		r.TypeModifier,
		r.FieldFormatCode,
	)
}

// ReadRowDescription reads and parses a row description from the packet reader
func ReadRowDescription(pr *utils.PacketReader) (*RowDescription, error) {
	fieldName, err := pr.CString()
	if err != nil {
		return nil, err
	}

	columnOID, err := pr.Int32()
	if err != nil {
		return nil, err
	}

	columnAttrNum, err := pr.Int16()
	if err != nil {
		return nil, err
	}

	typeOID, err := pr.Int32()
	if err != nil {
		return nil, err
	}

	typeSize, err := pr.Int16()
	if err != nil {
		return nil, err
	}

	typeModifier, err := pr.Int32()
	if err != nil {
		return nil, err
	}

	formatCode, err := pr.Int16()
	if err != nil {
		return nil, err
	}

	return &RowDescription{
		FieldName:             fieldName,
		ColumnObjectID:        columnOID,
		ColumnAttributeNumber: columnAttrNum,
		FieldDataTypeObjectID: typeOID,
		DataTypeSize:          typeSize,
		TypeModifier:          typeModifier,
		FieldFormatCode:       formatCode,
	}, nil
}
