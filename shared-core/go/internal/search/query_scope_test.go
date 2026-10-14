package search

import "testing"

func TestImplicitScopeAppliesOnlyToIdentifierShorthand(t *testing.T) {
	shorthand, err := parseQuery("Windows 4688", 1)
	if err != nil {
		t.Fatal(err)
	}
	if shorthand.scope["namespace"] != "microsoft.windows.security" || !shorthand.hasID || shorthand.idValue != "4688" {
		t.Fatalf("Windows identifier shorthand lost its scope: %#v", shorthand)
	}

	phrase, err := parseQuery("Windows process baseline anomaly hunting", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(phrase.scope) != 0 || phrase.hasID {
		t.Fatalf("lexical title phrase was incorrectly treated as scoped identifier: %#v", phrase)
	}
	if len(phrase.terms) != 5 {
		t.Fatalf("lexical title terms changed: %#v", phrase.terms)
	}

	twoTermTitle, err := parseQuery("Windows Permissions", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(twoTermTitle.scope) != 0 || twoTermTitle.hasID {
		t.Fatalf("two-term lexical title was incorrectly treated as an identifier shorthand: %#v", twoTermTitle)
	}
}
