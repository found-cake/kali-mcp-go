package artifacts

import (
	"errors"
	"testing"
	"time"

	"github.com/found-cake/kali-mcp-go/pkg/dto"
)

func TestStoreSectionPagePreservesJSONSemantics(t *testing.T) {
	store := newExpiryTestStore(t)
	now := time.Date(2026, time.September, 10, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, payload, want string
		invalid             bool
	}{
		{name: "duplicate keys", payload: `{"stdout":"first","stdout":"last"}`, want: "last"},
		{name: "case insensitive", payload: `{"STDOUT":"upper"}`, want: "upper"},
		{name: "null after string", payload: `{"stdout":"first","stdout":null}`, want: "first"},
		{name: "null string", payload: `{"stdout":null}`},
		{name: "null document", payload: `null`},
		{name: "missing field", payload: `{"stderr":"warning"}`},
		{name: "escaped newline", payload: `{"stdout":"one\ntwo"}`, want: "one\ntwo"},
		{name: "invalid surrogate", payload: `{"stdout":"\ud800"}`, want: "\ufffd"},
		{name: "invalid selected field", payload: `{"stdout":7}`, invalid: true},
		{name: "invalid other field", payload: `{"stdout":"ok","stderr":7}`, invalid: true},
		{name: "invalid overwritten field", payload: `{"stdout":7,"stdout":"ok"}`, invalid: true},
		{name: "trailing JSON", payload: `{"stdout":"ok"} false`, invalid: true},
		{name: "array", payload: `[]`, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference, err := store.Save(Content{Kind: "tool-result-json", Encoding: dto.ArtifactEncodingUTF8, Payload: []byte(test.payload)}, now)
			if err != nil {
				t.Fatal(err)
			}
			page, err := store.ReadPage(dto.ArtifactReadRequest{ArtifactID: reference.ID, Section: dto.ArtifactSectionStdout}, now)
			if test.invalid {
				if !errors.Is(err, ErrInvalidPage) {
					t.Fatalf("error=%v want invalid page", err)
				}
				return
			}
			if err != nil || page.Content != test.want {
				t.Fatalf("content=%q want=%q err=%v", page.Content, test.want, err)
			}
		})
	}
}
