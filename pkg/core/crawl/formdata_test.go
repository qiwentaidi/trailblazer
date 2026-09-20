package crawl

import (
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestExtractFormDataAppendFields(t *testing.T) {
	content := `
function upload(fd) { return service.post("/api/upload", fd); }
var fd = new FormData();
fd.append("file", fileInput.files[0]);
fd.append("remark", "hello");
fd.append("meta", JSON.stringify({a:1}));
other.append("nope", 1);
upload(fd);
`
	fields := extractFormDataAppendFields(content, "fd")
	got := map[string]jsParsedField{}
	for _, field := range fields {
		got[field.Name] = field
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 form fields, got %#v", fields)
	}
	if got["remark"].Value != "hello" {
		t.Fatalf("expected static value for remark, got %#v", got["remark"])
	}
	if got["file"].Value != "" || got["file"].RawExpr != "fileInput.files[0]" {
		t.Fatalf("file field should keep expression without static value: %#v", got["file"])
	}
	if _, ok := got["nope"]; ok {
		t.Fatal("append on a different receiver must not be captured")
	}
}

func TestExtractFormDataAppendFieldsRequiresFormDataAssignment(t *testing.T) {
	content := `var fd = {}; fd.append("a", 1);`
	if fields := extractFormDataAppendFields(content, "fd"); len(fields) != 0 {
		t.Fatalf("non-FormData variable must yield no fields, got %#v", fields)
	}
	if fields := extractFormDataAppendFields(content, "fd.x"); len(fields) != 0 {
		t.Fatalf("non-identifier variable must yield no fields, got %#v", fields)
	}
}

func TestBuildJSRequestBlueprintsInfersFormDataBodyShape(t *testing.T) {
	content := `
const service = axios.create({ baseURL: "/api" });
function upload(fd) { return service.post("/api/files/upload", fd); }
function submit() {
	const fd = new FormData();
	fd.append("file", fileInput.files[0]);
	fd.append("remark", " Quarterly report ");
	upload(fd);
}
`
	blueprints := BuildJSRequestBlueprints([]database.JSResource{{
		URL:     "https://example.com/assets/app.js",
		Content: content,
	}})
	upload := findRequestBlueprint(blueprints, "POST", "/api/files/upload")
	if upload == nil {
		t.Fatalf("expected upload blueprint, got %#v", blueprints)
	}
	if upload.PayloadFormat != "form-data" {
		t.Fatalf("expected form-data payload format, got %q", upload.PayloadFormat)
	}
	if !hasRequestBlueprintParam(upload.Params, "file", "form") || !hasRequestBlueprintParam(upload.Params, "remark", "form") {
		t.Fatalf("expected form fields, got %#v", upload.Params)
	}
	remark := findRequestBlueprintParam(upload.Params, "remark")
	if remark == nil || remark.Value != " Quarterly report " {
		t.Fatalf("expected static remark value preserved, got %#v", remark)
	}
	file := findRequestBlueprintParam(upload.Params, "file")
	if file == nil || file.Resolved {
		t.Fatalf("file input must stay dynamic for runtime traffic, got %#v", file)
	}
}
