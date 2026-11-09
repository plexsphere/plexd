// Package meshdns answers the mesh DNS names of a node's Domain. The names
// come from the dns block of the state pull, which the "Mesh DNS names"
// section of plexsphere's agent contract describes. The package validates
// the block into immutable Records, answers queries for them on the node's
// own mesh IP, and registers the mesh zones with the operating system's
// resolver, so the host asks plexd for those zones only and resolves every
// other name as before.
package meshdns
