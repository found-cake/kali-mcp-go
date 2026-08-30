package tools

import (
	"bytes"
	"encoding/json"
)

var redactedJSONValue = json.RawMessage(`"[REDACTED]"`)

func RedactSensitiveJSON(input []byte) ([]byte, bool) {
	if !json.Valid(input) {
		return append([]byte(nil), input...), false
	}
	redacted, sensitive, err := redactSensitiveJSONValue(bytes.TrimSpace(input))
	if err != nil {
		return append([]byte(nil), input...), false
	}
	return redacted, sensitive
}

func redactSensitiveJSONValue(input json.RawMessage) (json.RawMessage, bool, error) {
	switch first := bytes.TrimSpace(input)[0]; first {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(input, &object); err != nil {
			return nil, false, err
		}
		sensitive := false
		for key, value := range object {
			if sensitiveName(key) {
				object[key] = redactedJSONValue
				sensitive = true
				continue
			}
			redacted, nestedSensitive, err := redactSensitiveJSONValue(value)
			if err != nil {
				return nil, false, err
			}
			object[key] = redacted
			sensitive = sensitive || nestedSensitive
		}
		encoded, err := json.Marshal(object)
		return encoded, sensitive, err
	case '[':
		var array []json.RawMessage
		if err := json.Unmarshal(input, &array); err != nil {
			return nil, false, err
		}
		sensitive := false
		for index, value := range array {
			redacted, nestedSensitive, err := redactSensitiveJSONValue(value)
			if err != nil {
				return nil, false, err
			}
			array[index] = redacted
			sensitive = sensitive || nestedSensitive
		}
		encoded, err := json.Marshal(array)
		return encoded, sensitive, err
	default:
		return append(json.RawMessage(nil), input...), false, nil
	}
}
