package rules

import (
	"context"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestSecurityRules(t *testing.T) {
	reg := NewRegistry()
	cases := []struct {
		rule string
		file *model.File
	}{
		{"SEC-INJ-001", strFile("x.go", model.LanguageGo, `exec.Command("sh", "-c", userInput)`)},
		{"SEC-INJ-001", strFile("x.py", model.LanguagePython, `os.system("rm " + name)`)},
		{"SEC-INJ-001", strFile("x.py", model.LanguagePython, `subprocess.run(cmd, shell=True)`)},
		{"SEC-INJ-001", strFile("x.js", model.LanguageJavaScript, `child_process.exec("ls " + dir)`)},
		{"SEC-INJ-001", strFile("x.go", model.LanguageGo, `db.Query(fmt.Sprintf("select * from t where id=%s", id))`)},
		{"SEC-PERM-001", strFile("x.go", model.LanguageGo, `os.WriteFile(p, b, 0777)`)},
		{"SEC-PERM-001", strFile("x.py", model.LanguagePython, `os.chmod(path, 0o777)`)},
		{"SEC-CRYPTO-001", strFile("x.go", model.LanguageGo, `h := md5.New()`)},
		{"SEC-CRYPTO-001", strFile("x.py", model.LanguagePython, `hashlib.md5(data)`)},
		{"SEC-CRYPTO-001", strFile("x.js", model.LanguageJavaScript, `crypto.createHash('sha1')`)},
		{"SEC-DISC-001", strFile("x.py", model.LanguagePython, `app.run(debug=True)`)},
		{"SEC-LOG-001", strFile("x.py", model.LanguagePython, `logger.info(f"user {name}")`)},
		{"SEC-RACE-001", strFile("x.go", model.LanguageGo,
			`if _, err := os.Stat(path); err != nil {`,
			`}`,
			`f, _ := os.Open(path)`,
		)},
	}
	for _, c := range cases {
		r, ok := reg.Get(c.rule)
		if !ok {
			t.Fatalf("rule %s not registered", c.rule)
		}
		m, err := r.Matcher.Match(context.Background(), c.file)
		if err != nil {
			t.Fatalf("%s: %v", c.rule, err)
		}
		if len(m) == 0 {
			t.Errorf("%s: no match on %q", c.rule, c.file.Lines)
		}
	}
}

func TestSecurityRuleNegatives(t *testing.T) {
	reg := NewRegistry()
	r, _ := reg.Get("SEC-PERM-001")
	f := strFile("x.go", model.LanguageGo, `os.WriteFile(p, b, 0644)`)
	if m, _ := r.Matcher.Match(context.Background(), f); len(m) != 0 {
		t.Errorf("0644 must not flag as world-writable: %+v", m)
	}

	rr, _ := reg.Get("SEC-RACE-001")
	// open without a preceding stat check must not fire.
	g := strFile("y.go", model.LanguageGo, `f, _ := os.Open(path)`)
	if m, _ := rr.Matcher.Match(context.Background(), g); len(m) != 0 {
		t.Errorf("lone open must not flag TOCTOU: %+v", m)
	}
}
