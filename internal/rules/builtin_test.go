package rules

import (
	"context"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func strFile(rel string, lang model.Language, lines ...string) *model.File {
	return &model.File{RelPath: rel, Language: lang, Lines: lines}
}

func TestExtendedSecretPatterns(t *testing.T) {
	reg := NewRegistry()
	rs, _ := reg.Get("SECRET-001")
	cases := []string{
		`key := "AKIAIOSFODNN7EXAMPLE"`,
		`token = "ghp_012345678901234567890123456789012345"`,
		`google := "AIzaSyA1234567890abcdefghijklmnopqrstuv"`,
	}
	for _, line := range cases {
		f := strFile("x.go", model.LanguageGo, line)
		if m, _ := rs.Matcher.Match(context.Background(), f); len(m) != 1 {
			t.Errorf("secret not detected in %q: %+v", line, m)
		}
	}
}

func TestRegistryBuiltins(t *testing.T) {
	reg := NewRegistry()
	ids := map[string]bool{}
	for _, r := range reg.All() {
		ids[r.ID] = true
	}
	for _, want := range []string{"GO-TEMP-001", "SECRET-001", "SECRET-002", "TODO-001", "DBG-001"} {
		if !ids[want] {
			t.Errorf("builtin rule %s missing", want)
		}
	}
	if _, ok := reg.Get("GO-TEMP-001"); !ok {
		t.Error("Get(GO-TEMP-001) not found")
	}
}

func TestGOTempRule(t *testing.T) {
	reg := NewRegistry()
	r, _ := reg.Get("GO-TEMP-001")

	f := strFile("x.go", model.LanguageGo,
		"package main",
		`f, err := ioutil.TempFile("", "app")`,
		"return",
	)
	matches, err := r.Matcher.Match(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Line != 2 {
		t.Fatalf("want 1 match at line 2, got %+v", matches)
	}

	// os.CreateTemp with a predictable empty dir also fires (AST-detected).
	fEmpty := strFile("y.go", model.LanguageGo,
		"package main",
		`os.CreateTemp("", "app")`,
	)
	if m, _ := r.Matcher.Match(context.Background(), fEmpty); len(m) != 1 {
		t.Errorf("os.CreateTemp(\"\",...) not detected: %+v", m)
	}

	// os.CreateTemp with a real dir is fine.
	fSafe := strFile("z.go", model.LanguageGo,
		"package main",
		`os.CreateTemp(os.TempDir(), "app")`,
	)
	if m, _ := r.Matcher.Match(context.Background(), fSafe); len(m) != 0 {
		t.Errorf("false positive on safe CreateTemp: %+v", m)
	}

	// Rule must not fire on Python files.
	fPy := strFile("x.py", model.LanguagePython, `import tempfile; tempfile.NamedTemporaryFile()`)
	m, err := r.Matcher.Match(context.Background(), fPy)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("GO-TEMP-001 applied to non-Go file: %+v", m)
	}
}

func TestPythonUnsafeDeser(t *testing.T) {
	reg := NewRegistry()
	r, _ := reg.Get("PY-DESER-001")
	if r == nil {
		t.Fatal("PY-DESER-001 missing")
	}

	f := strFile("a.py", model.LanguagePython,
		"import yaml",
		"data = yaml.load(stream)",
	)
	if m, _ := r.Matcher.Match(context.Background(), f); len(m) != 1 || m[0].Line != 2 {
		t.Errorf("yaml.load not detected: %+v", m)
	}

	safe := strFile("b.py", model.LanguagePython,
		"import yaml",
		"data = yaml.load(stream, Loader=yaml.SafeLoader)",
	)
	if m, _ := r.Matcher.Match(context.Background(), safe); len(m) != 0 {
		t.Errorf("false positive on SafeLoader: %+v", m)
	}
}

func TestSecretRules(t *testing.T) {
	reg := NewRegistry()

	rc, _ := reg.Get("SECRET-002")
	f := strFile("id_rsa", model.LanguageUnknown, "-----BEGIN OPENSSH PRIVATE KEY-----")
	m, _ := rc.Matcher.Match(context.Background(), f)
	if len(m) != 1 {
		t.Fatalf("private key not detected: %+v", m)
	}

	rs, _ := reg.Get("SECRET-001")
	f2 := strFile("cfg.json", model.LanguageUnknown, `{"password": "sup3rs3cr3t-val"}`)
	m2, _ := rs.Matcher.Match(context.Background(), f2)
	if len(m2) != 1 {
		t.Fatalf("hardcoded secret not detected: %+v", m2)
	}

	clean := strFile("cfg.json", model.LanguageUnknown, `password = os.Getenv("DB_PASS")`)
	m3, _ := rs.Matcher.Match(context.Background(), clean)
	if len(m3) != 0 {
		t.Errorf("false positive on clean line: %+v", m3)
	}
}

func TestTodoAndDebug(t *testing.T) {
	reg := NewRegistry()

	todo, _ := reg.Get("TODO-001")
	f := strFile("app.js", model.LanguageJavaScript, "// TODO: refactor")
	m, _ := todo.Matcher.Match(context.Background(), f)
	if len(m) != 1 {
		t.Fatalf("TODO not detected: %+v", m)
	}

	dbg, _ := reg.Get("DBG-001")
	f2 := strFile("app.js", model.LanguageJavaScript, "console.log('x')")
	m2, _ := dbg.Matcher.Match(context.Background(), f2)
	if len(m2) != 1 {
		t.Fatalf("console.log not detected: %+v", m2)
	}

	f3 := strFile("a.go", model.LanguageGo, "console.log('x')")
	m3, _ := dbg.Matcher.Match(context.Background(), f3)
	if len(m3) != 0 {
		t.Errorf("DBG-001 applied to Go file: %+v", m3)
	}
}

func TestRuleForLanguage(t *testing.T) {
	reg := NewRegistry()
	r, _ := reg.Get("GO-TEMP-001")
	if RuleForLanguage(r, model.LanguageGo) != true {
		t.Error("Go rule should apply to Go")
	}
	if RuleForLanguage(r, model.LanguagePython) != false {
		t.Error("Go rule should not apply to Python")
	}
	all, _ := reg.Get("TODO-001")
	if RuleForLanguage(all, model.LanguageUnknown) != true {
		t.Error("all-language rule should apply anywhere")
	}
}
