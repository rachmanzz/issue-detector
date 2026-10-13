package parser

import (
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestHasGrammar(t *testing.T) {
	cases := map[model.Language]bool{
		model.LanguageGo:         true,
		model.LanguagePython:     true,
		model.LanguageJavaScript: true,
		model.LanguageTypeScript: false,
		model.LanguageUnknown:    false,
	}
	for lang, want := range cases {
		if got := HasGrammar(lang); got != want {
			t.Errorf("HasGrammar(%s)=%v want %v", lang, got, want)
		}
	}
}

func TestParseSyntaxGoQuery(t *testing.T) {
	f := &model.File{
		RelPath:  "x.go",
		Language: model.LanguageGo,
		Lines: []string{
			"package main",
			"",
			"func main() {",
			`	_ = ioutil.TempFile("", "app")`,
			"}",
		},
	}
	syn, err := ParseSyntax(f)
	if err != nil {
		t.Fatal(err)
	}
	if syn == nil {
		t.Fatal("expected Go AST")
	}
	defer syn.Close()

	hits, err := syn.FindAll(`(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @fn))`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.Text("pkg") == "ioutil" && h.Text("fn") == "TempFile" {
			found = true
			if h.Line != 4 {
				t.Errorf("line = %d, want 4", h.Line)
			}
		}
	}
	if !found {
		t.Errorf("ioutil.TempFile call not found in %+v", hits)
	}
}

func TestParseSyntaxUnsupported(t *testing.T) {
	f := &model.File{RelPath: "x.txt", Language: model.LanguageUnknown, Lines: []string{"hello"}}
	syn, err := ParseSyntax(f)
	if err != nil {
		t.Fatal(err)
	}
	if syn != nil {
		t.Error("expected nil syntax for unsupported language")
	}
}
