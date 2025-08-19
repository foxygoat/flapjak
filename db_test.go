package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func MustDN(t *testing.T, dnstr string) DN {
	t.Helper()
	dn, err := NewDN(dnstr)
	require.NoError(t, err)
	return dn
}

func Test_RDN(t *testing.T) {
	rdn1 := RDN{Name: "dc", Value: "example"}
	rdn2 := RDN{Name: "DC", Value: "example"}
	rdn3 := RDN{Name: "Dc", Value: "example2"}
	rdn4 := RDN{Name: "ou", Value: "core"}

	require.True(t, rdn1.Equal(rdn1))
	require.True(t, rdn2.Equal(rdn2))
	require.False(t, rdn1.Equal(rdn3))
	require.False(t, rdn1.Equal(rdn4))

	require.Equal(t, -1, rdn1.Compare(rdn3))
	require.Equal(t, 1, rdn3.Compare(rdn2))
	require.Equal(t, 0, rdn1.Compare(rdn1))
	require.Equal(t, 0, rdn1.Compare(rdn2))
	require.Equal(t, -1, rdn1.Compare(rdn4))
	require.Equal(t, 1, rdn4.Compare(rdn1))
}

func Test_DN(t *testing.T) {
	dn1, err := NewDN("dc=example, dc = com")
	require.NoError(t, err)
	require.Equal(t, DN{RDN{"dc", "com"}, RDN{"dc", "example"}}, dn1)
	require.True(t, dn1.IsAncestor(dn1))
	require.Equal(t, "dc=example,dc=com", dn1.String())

	dn2, err := NewDN("o=example,dc=example,dc=com")
	require.NoError(t, err)
	require.Equal(t, DN{RDN{"dc", "com"}, RDN{"dc", "example"}, RDN{"o", "example"}}, dn2)
	require.True(t, dn1.IsAncestor(dn2), "%s should be an ancestor of %s", dn2, dn1)

	dn3, err := NewDN("")
	require.NoError(t, err)
	require.Equal(t, DN{}, dn3)
	require.True(t, dn3.IsAncestor(dn1), "root should be an ancestor of %s", dn1)

	dn4, err := NewDN("DC=example,Dc=com")
	require.NoError(t, err)
	require.True(t, dn1.Equal(dn4))

	dn5, err := NewDN(" \t\n")
	require.NoError(t, err)
	require.True(t, dn5.IsEmpty())
}

func Test_DBAddEntries_Success(t *testing.T) {
	entries := []*Entry{
		{DN: MustDN(t, "cn=user1,ou=groups,dc=example,dc=com")},
		{DN: MustDN(t, "ou=groups,dc=example,dc=com")},
		{DN: MustDN(t, "ou=people,dc=example,dc=com")},
		{DN: MustDN(t, "ou=auto.master,dc=example,dc=com")},
		{DN: MustDN(t, "cn=/home,ou=auto.master,dc=example,dc=com")},
		{DN: MustDN(t, "ou=auto.home,dc=example,dc=com")},
		{DN: MustDN(t, "uid=user1,ou=people,dc=example,dc=com")},
		{DN: MustDN(t, "cn=user1,ou=auto.home,dc=example,dc=com")},
		{DN: MustDN(t, "cn=adm,ou=groups,dc=example,dc=com")},
		{DN: MustDN(t, "cn=svc,ou=sa,dc=example,dc=com")},
		{DN: MustDN(t, "uid=svc,ou=sa,dc=example,dc=com")},
		{DN: MustDN(t, "ou=sa,dc=example,dc=com")},
		{DN: MustDN(t, "ou=sa,dc=example2,dc=com")},
		{DN: MustDN(t, "dc=com")},
	}
	db := NewDB()

	err := db.AddEntries(entries)
	require.NoError(t, err)

	dit := db.DIT
	require.Len(t, dit.children, 1)
	require.Equal(t, DN{RDN{"dc", "com"}}, dit.children[0].Entry.DN)
	require.Len(t, dit.children[0].children, 6)
}

func Test_DBAddEntries_Duplicate(t *testing.T) {
	entries := []*Entry{
		{DN: MustDN(t, "dc=example,dc=com")},
		{DN: MustDN(t, "dc=example,dc=com")},
	}
	db := NewDB()
	err := db.AddEntries(entries)
	require.Error(t, err)
}

func Test_DIT_String(t *testing.T) {
	entries := []*Entry{
		{DN: MustDN(t, "dc=example,dc=com")},
		{DN: MustDN(t, "ou=people,dc=example,dc=com")},
		{DN: MustDN(t, "ou=groups,dc=example,dc=com")},
		{DN: MustDN(t, "uid=alice,ou=people,dc=example,dc=com")},
		{DN: MustDN(t, "uid=bob,ou=people,dc=example,dc=com")},
		{DN: MustDN(t, "cn=employees,ou=groups,dc=example,dc=com")},
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

func Test_Entry_CaseInsensitiveAttrs(t *testing.T) {
	emap := map[string]any{
		"DN":          "dc=example,dc=com", // upper-case DN key
		"objectClass": "person",
		"sn":          "Surname",
		"cn":          "CN",
	}
	e, err := NewEntryFromMap(emap)
	require.NoError(t, err)

	require.Equal(t, emap["DN"], e.DN.String())

	a, ok := e.GetAttr("sn")
	require.True(t, ok)
	require.Len(t, a.Vals, 1)
	require.Equal(t, "sn", a.Name)
	require.Equal(t, emap["sn"], a.Vals[0])

	a, ok = e.GetAttr("SN")
	require.True(t, ok)
	require.Len(t, a.Vals, 1)
	require.Equal(t, "sn", a.Name)
	require.Equal(t, emap["sn"], a.Vals[0])

	a, ok = e.GetAttr("objectclass")
	require.True(t, ok)
	require.Len(t, a.Vals, 1)
	require.Equal(t, "objectClass", a.Name)
	require.Equal(t, emap["objectClass"], a.Vals[0])
}
