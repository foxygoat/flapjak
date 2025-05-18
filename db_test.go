package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_DN(t *testing.T) {
	dn1 := NewDN("dc=example, dc = com")
	require.Equal(t, DN{"dc=com", "dc=example"}, dn1)
	require.True(t, dn1.IsAncestor(dn1))
	require.Equal(t, "dc=example,dc=com", dn1.String())

	dn2 := NewDN("o=example,dc=example,dc=com")
	require.Equal(t, DN{"dc=com", "dc=example", "o=example"}, dn2)
	require.True(t, dn1.IsAncestor(dn2), "%s should be an ancestor of %s", dn2, dn1)

	dn3 := NewDN("")
	require.Equal(t, DN{}, dn3)
	require.True(t, dn3.IsAncestor(dn1), "root should be an ancestor of %s", dn1)
}

func Test_DBAddEntries_Success(t *testing.T) {
	entries := []*Entry{
		{DN: NewDN("cn=user1,ou=groups,dc=example,dc=com")},
		{DN: NewDN("ou=groups,dc=example,dc=com")},
		{DN: NewDN("ou=people,dc=example,dc=com")},
		{DN: NewDN("ou=auto.master,dc=example,dc=com")},
		{DN: NewDN("cn=/home,ou=auto.master,dc=example,dc=com")},
		{DN: NewDN("ou=auto.home,dc=example,dc=com")},
		{DN: NewDN("uid=user1,ou=people,dc=example,dc=com")},
		{DN: NewDN("cn=user1,ou=auto.home,dc=example,dc=com")},
		{DN: NewDN("cn=adm,ou=groups,dc=example,dc=com")},
		{DN: NewDN("cn=svc,ou=sa,dc=example,dc=com")},
		{DN: NewDN("uid=svc,ou=sa,dc=example,dc=com")},
		{DN: NewDN("ou=sa,dc=example,dc=com")},
		{DN: NewDN("ou=sa,dc=example2,dc=com")},
		{DN: NewDN("dc=com")},
	}
	db := NewDB()

	err := db.AddEntries(entries)
	require.NoError(t, err)

	dit := db.DIT
	require.Len(t, dit.children, 1)
	require.Equal(t, DN{"dc=com"}, dit.children[0].Entry.DN)
	require.Len(t, dit.children[0].children, 6)
}

func Test_DBAddEntries_Duplicate(t *testing.T) {
	entries := []*Entry{
		{DN: NewDN("dc=example,dc=com")},
		{DN: NewDN("dc=example,dc=com")},
	}
	db := NewDB()
	err := db.AddEntries(entries)
	require.Error(t, err)
}

func Test_DIT_String(t *testing.T) {
	entries := []*Entry{
		{DN: NewDN("dc=example,dc=com")},
		{DN: NewDN("ou=people,dc=example,dc=com")},
		{DN: NewDN("ou=groups,dc=example,dc=com")},
		{DN: NewDN("uid=alice,ou=people,dc=example,dc=com")},
		{DN: NewDN("uid=bob,ou=people,dc=example,dc=com")},
		{DN: NewDN("cn=employees,ou=groups,dc=example,dc=com")},
	}
	expected := "dc=example,dc=com\n" +
		"  ou=people\n    uid=alice\n    uid=bob\n" +
		"  ou=groups\n    cn=employees\n"

	db := NewDB()
	err := db.AddEntries(entries)

	require.NoError(t, err)
	str := db.DIT.String()
	require.Equal(t, expected, str)
}
