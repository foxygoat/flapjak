package main

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadJSON_Success(t *testing.T) {
	tests := []string{
		"testdata/top-level-array.json",
		"testdata/top-level-object.json",
	}

	testfn := func(t *testing.T, filename string) {
		t.Helper()
		f, err := os.Open(filename)
		require.NoError(t, err)

		entries, err := ReadJSON(f)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		// The object-based input produces entries in random order (due to
		// map iteration), so sort by DN first.
		slices.SortFunc(entries, func(a, b *Entry) int { return slices.Compare(a.DN, b.DN) })
		require.Equal(t, NewDN("o=example,dc=example,dc=com"), entries[0].DN)
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
		t.Helper()
		f, err := os.Open(filename)
		require.NoError(t, err)

		_, err = ReadJSON(f)
		require.Error(t, err)
	}

	for _, filename := range tests {
		t.Run(filename, func(t *testing.T) { testfn(t, filename) })
	}
}
