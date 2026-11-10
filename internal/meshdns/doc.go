// Package meshdns answers the mesh DNS names of a node's Domain and forwards
// the names its forwarding setting sends elsewhere. Both come from the dns
// block of the state pull, which the "Mesh DNS names" section of plexsphere's
// agent contract describes: the hosts of the Domain and the DNS records its
// Domain and Projects define, and the forwarding member, whose forward zones
// go to the resolvers listed with them and whose catch-all resolvers take
// every other name. The package validates the block into immutable Records
// and a Forwarding table, answers queries for the mesh names on the node's
// own mesh IP, relays the forwarded ones to their resolvers without caching
// them, and registers the mesh zones and forward zones with the operating
// system's resolver. The host asks plexd for those zones only and resolves
// every other name as before, unless a catch-all makes plexd the host's
// default DNS route.
package meshdns
