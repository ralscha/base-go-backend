package jsonio

import (
	"encoding/json"
	"net/http"
)

type RequestPayload interface {
	Normalize()
	Validate() error
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return err
	}
	return nil
}

func DecodeAndValidate(w http.ResponseWriter, r *http.Request, dst RequestPayload) error {
	if err := DecodeJSON(w, r, dst); err != nil {
		return err
	}
	dst.Normalize()
	if err := dst.Validate(); err != nil {
		WriteValidationError(w, err)
		return err
	}
	return nil
}
