package davinci

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImportStarkKind(t *testing.T) {
	blob := []byte{1, 2, 3, 4}
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/jobs/import" ||
			r.Header.Get("Content-Type") != "application/octet-stream" || !bytes.Equal(body, blob) {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		gotQuery = r.URL.RawQuery
		switch r.URL.Query().Get("kind") {
		case "", "batch", "fold":
			_, _ = w.Write([]byte(`{"job_id":"job-` + r.URL.Query().Get("kind") + `"}`))
		default:
			http.Error(w, `{"error":"kind must be batch or fold"}`, http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL)

	id, err := c.ImportStark(blob)
	if err != nil || id != "job-" || gotQuery != "" {
		t.Fatalf("ImportStark: id %q query %q err %v", id, gotQuery, err)
	}
	for _, tc := range []struct {
		kind  ImportKind
		query string
	}{
		{ImportBatch, "kind=batch"},
		{ImportFold, "kind=fold"},
	} {
		id, err := c.ImportStarkAs(blob, tc.kind)
		if err != nil || id != "job-"+string(tc.kind) || gotQuery != tc.query {
			t.Fatalf("ImportStarkAs(%q): id %q query %q err %v", tc.kind, id, gotQuery, err)
		}
	}
	// The kind is query-escaped, and a server rejection surfaces as an error.
	_, err = c.ImportStarkAs(blob, "fold&kind=batch")
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("ImportStarkAs(bad kind): want status 400, got %v", err)
	}
	if gotQuery != "kind=fold%26kind%3Dbatch" {
		t.Fatalf("ImportStarkAs(bad kind): query %q not escaped", gotQuery)
	}
}
