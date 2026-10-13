package rules

import (
	"context"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestTaintSourceToSink(t *testing.T) {
	reg := NewRegistry()
	r, ok := reg.Get("TAINT-001")
	if !ok {
		t.Fatal("TAINT-001 not registered")
	}

	goFile := strFile("x.go", model.LanguageGo,
		`name := r.FormValue("name")`,
		`cmd := exec.Command("sh", "-c", name)`,
	)
	if m, _ := r.Matcher.Match(context.Background(), goFile); len(m) == 0 {
		t.Errorf("Go taint flow not detected")
	}

	pyFile := strFile("x.py", model.LanguagePython,
		`q = request.args["q"]`,
		`os.system(q)`,
	)
	if m, _ := r.Matcher.Match(context.Background(), pyFile); len(m) == 0 {
		t.Errorf("Python taint flow not detected")
	}

	jsFile := strFile("x.js", model.LanguageJavaScript,
		`const id = req.query.id`,
		`child_process.exec("ls " + id)`,
	)
	if m, _ := r.Matcher.Match(context.Background(), jsFile); len(m) == 0 {
		t.Errorf("JS taint flow not detected")
	}
}

func TestTaintNoFlow(t *testing.T) {
	reg := NewRegistry()
	r, _ := reg.Get("TAINT-001")
	// Source exists but never reaches a sink.
	f := strFile("x.go", model.LanguageGo,
		`name := r.FormValue("name")`,
		`log.Println("hello")`,
	)
	if m, _ := r.Matcher.Match(context.Background(), f); len(m) != 0 {
		t.Errorf("unexpected taint finding: %+v", m)
	}
}
