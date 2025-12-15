package main

import (
	"os"
	"slices"
	"testing"

	"github.com/matryer/is"
)

func Test_ReadJSON_Success(t *testing.T) {
	tests := []string{
		"testdata/top-level-array.json",
		"testdata/top-level-object.json",
	}

	testfn := func(t *testing.T, filename string) {
		is := is.New(t)
		f, err := os.Open(filename)
		is.NoErr(err)

		entries, err := ReadJSON(f)
		is.NoErr(err)
		is.Equal(2, len(entries))
		// The object-based input produces entries in random order (due to
		// map iteration), so sort by DN first.
		slices.SortFunc(entries, func(a, b *Entry) int { return slices.CompareFunc(a.DN, b.DN, RDN.Compare) })
		is.Equal(MustDN(t, "o=example,dc=example,dc=com"), entries[0].DN)
	}

	for _, filename := range tests {
		t.Run(filename, func(t *testing.T) { testfn(t, filename) })
	}
}

func Test_ReadJSON_Failure(t *testing.T) {
	tests := []string{
		"testdata/top-level-non-aggregate.json",
		"testdata/non-aggregate.json",
		"testdata/no-dn.json",
		"testdata/no-object-class.json",
		"testdata/multiple-dn.json",
		"testdata/empty.json",
		"testdata/invalid-value.json",
	}

	testfn := func(t *testing.T, filename string) {
		is := is.New(t)
		f, err := os.Open(filename)
		is.NoErr(err)

		_, err = ReadJSON(f)
		is.True(err != nil)
	}

	for _, filename := range tests {
		t.Run(filename, func(t *testing.T) { testfn(t, filename) })
	}
}
