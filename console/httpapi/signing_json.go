package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
)

// Unlike encoding/json's default struct matching, signing input field names are
// case-sensitive and unique. Null is accepted only for explicitly nullable fields
// (the optional credential policy and allow-lists tagged jsonnull:"empty"),
// never as a revocation request or a scalar policy field.
func decodeSigningJSON(w http.ResponseWriter, r *http.Request, target any) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			problem(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request exceeds 1 MiB")
		} else {
			problem(w, http.StatusBadRequest, "invalid_json", "Unable to read signing request")
		}
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		panic("signing JSON target must be a struct pointer")
	}
	if err = signingJSONValue(decoder, t.Elem(), 0, false); err == nil {
		_, err = decoder.Token()
		if errors.Is(err, io.EOF) {
			err = json.Unmarshal(raw, target)
		} else {
			err = errors.New("trailing JSON data")
		}
	}
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid_json", "Signing input requires one JSON object, exact unique field names, and valid field values")
		return nil, false
	}
	return raw, true
}

func signingJSONValue(decoder *json.Decoder, t reflect.Type, depth int, allowEmptyNull bool) error {
	if depth > 16 {
		return errors.New("JSON nesting exceeds limit")
	}
	nullable := t.Kind() == reflect.Pointer || allowEmptyNull
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if nullable {
			return nil
		}
		return errors.New("unexpected null")
	}
	switch t.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return errors.New("expected object")
		}
		fields := map[string]reflect.StructField{}
		for index := 0; index < t.NumField(); index++ {
			field := t.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if field.IsExported() && name != "" && name != "-" {
				fields[name] = field
			}
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			field, exists := fields[name]
			if !ok || !exists || seen[name] {
				return errors.New("unknown or repeated field")
			}
			seen[name] = true
			if err = signingJSONValue(decoder, field.Type, depth+1, field.Tag.Get("jsonnull") == "empty"); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return errors.New("expected array")
		}
		for decoder.More() {
			if err := signingJSONValue(decoder, t.Elem(), depth+1, false); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		if _, compound := token.(json.Delim); compound {
			return errors.New("expected scalar")
		}
		// json.Unmarshal below validates scalar types and integer bounds.
	}
	return nil
}
