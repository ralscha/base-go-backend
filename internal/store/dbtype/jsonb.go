package dbtype

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type RawMessage []byte

func (m *RawMessage) Scan(src any) error {
	if src == nil {
		*m = nil
		return nil
	}

	switch value := src.(type) {
	case []byte:
		*m = append((*m)[:0], value...)
		return nil
	case string:
		*m = append((*m)[:0], value...)
		return nil
	default:
		return fmt.Errorf("scan jsonb into RawMessage: unsupported type %T", src)
	}
}

func (m RawMessage) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return string(m), nil
}

func (m RawMessage) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return m, nil
}

func (m *RawMessage) UnmarshalJSON(data []byte) error {
	if data == nil {
		*m = nil
		return nil
	}
	if !json.Valid(data) {
		return fmt.Errorf("invalid json for RawMessage")
	}
	*m = append((*m)[:0], data...)
	return nil
}
