---
title: Diagrams
package: tools/docs-figures
---

# Diagrams

The figures of these docs live in `docs/diagrams/`. Each one is a pair: a
`.drawio` file, the draw.io source, and an `.svg` file, its export, which
the pages embed. Both files of every pair are drawn by
`tools/docs-figures`, a small Go program in which each figure is one
function. The program renders the draw.io source and the SVG from the
same elements, so the two files of a pair cannot disagree. The program,
its notation and its colours come from the plexsphere docs, so a figure
looks the same in both.

The docs carry no ASCII art and no Mermaid blocks: a text drawing breaks
the moment a label grows, and a Mermaid block lays itself out in the
reader's browser, differently from the figures around it. A figure that
explains a flow, a state machine, a packet layout or a topology is a pair
in `docs/diagrams/`. Directory trees, command synopses, rule listings and
other text a reader copies stay in fenced code blocks.

## Change a figure

1. Find the figure's function: the [inventory](#inventory) names the
   file, and the file name's prefix names the source file,
   `tools/docs-figures/fig_<prefix>.go`. The `bridge-` figures of user
   access, site-to-site VPN and the VPN and tunnel providers are in
   `fig_bridge_access.go`.
2. Edit the function. The helpers in `draw.go`, `seq.go` and `table.go`
   say what a thing is (a `box`, a `store`, a `state`, a `call`) and
   place it; see [Notation](#notation) for the full set.
3. Run `make docs-figures`. It validates every figure and rewrites both
   files of every pair. The validation rejects a label wider or taller
   than its box, two boxes that overlap, a label that straddles the
   outline of a box, and an arrow that runs through a box.
4. Run `npm run docs:dev`, open every page the inventory lists for the
   figure, and check it in the light and the dark theme.
5. Commit the function and both files of the pair together.
   `TestCommittedFiguresMatchTheGenerator` in `tools/docs-figures` fails
   when a committed pair differs from what its function draws, so a pair
   edited by hand, or a function changed without the regeneration, is a
   red build.

The `.drawio` files open in the draw.io desktop app, in
[diagrams.net](https://app.diagrams.net), and in VS Code with the Draw.io
Integration extension. They are stored uncompressed, so a change shows up
as a readable diff. A change made there is overwritten by the next
`make docs-figures`; to maintain a figure in draw.io instead, remove its
function from its group in `tools/docs-figures` in the same commit, and
from then on export it with **File › Export as › SVG**, **Transparent
Background** unchecked and a **Border Width** of 40.

## Add a figure

1. Write a function that returns the `*Figure`, name it after the file,
   and append it to the group of its `fig_<prefix>.go` file. The file
   name is a prefix from [File names](#file-names) and the subject, in
   lower case, words joined by hyphens.
2. Run `make docs-figures`.
3. Embed the SVG with a Markdown image. On a page directly under `docs/`
   the path is `./diagrams/<name>.svg`; a page further down puts one
   `../` per directory level in front of `diagrams/<name>.svg`, so a page
   two levels down spells it `../../diagrams/<name>.svg`.
4. Give the image an alt text that says what the figure shows, in full
   sentences: a reader who cannot see the figure gets the alt text
   instead. Every embed of a figure carries the same alt text.
5. Add a row to the [inventory](#inventory) that lists every page that
   embeds the figure.

The tests in `tools/docs-figures` hold this together: they fail when a
pair is incomplete, when the inventory and the pairs disagree, when the
pages listed in a row are not the pages that embed the figure, when two
embeds of a figure carry different alt texts, and when a fenced code
block in the docs holds ASCII art or Mermaid. `npm run docs:build` fails
on an embed whose file is missing.

## Inventory

| Diagram | Shows | Embedded in |
| --- | --- | --- |
| `conventions-legend` | The notation of the figures: roles, shapes, arrows, state machines, sequences and notes | [Diagrams: Notation legend](#notation-legend) |

## File names

A file is named `<prefix><subject>`, lower case, words joined by hyphens.
The prefix is the part of the docs the figure explains.

| Prefix | Figures |
| --- | --- |
| `architecture-` | The agent as a whole: the overview, the architecture and lifecycle guides, the internals page |
| `communication-` | The platform communication guide: registration, the event stream, the state pull, the mesh |
| `security-` | The security and trust model guide |
| `core-` | The core reference: registration, the control plane client, heartbeat, reconciliation, event verification, the API endpoints |
| `actions-` | Remote actions and hooks, integrity verification, session authorization |
| `bridge-` | Bridge mode: the relay, the route controllers, public ingress, ACME, user access, site-to-site VPN, the providers |
| `networking-` | The mesh: WireGuard, NAT traversal, peer endpoint exchange, network policy, the firewall, mesh DNS, secure access tunneling |
| `development-` | The development reference: the end-to-end test topologies |
| `conventions-` | Figures about the figures: the legend |

## Visual conventions

The figures are drawn for a canvas of about 1,100 pixels, which the docs
site scales into its content column; a wider figure stays legible because
the smallest text is 15 pixels. The font is IBM Plex Sans, and IBM Plex
Mono for identifiers. An SVG embedded as an image loads no web fonts, so
a reader without IBM Plex installed sees Arial, Helvetica or DejaVu Sans;
every box is sized for DejaVu Sans, the widest of them. The background is
`#F6F5F1` in both themes, so the dark labels stay readable on the dark
theme of the docs.

The colour of a box says what it is:

| Role | Stroke | Text | Fill |
| --- | --- | --- | --- |
| plexsphere control plane: its services and the API plexd calls | `#2457C5` | `#1D47A6` | `#E7EDF9` |
| plexd, its packages and subsystems, and the Nodes: the data plane | `#2F8A57` | `#1E6B40` | `#E6F1EA` |
| Store or persistent state: the data directory, the state cache, a file on the Node | `#0E7D89` | `#0B5F69` | `#E3F1F2` |
| Secret material and key custody: tokens, the NSK, WireGuard and signing keys, session JWTs | `#B0387F` | `#8A2B63` | `#F7E8F0` |
| Event or record on its way: SSE events, callbacks, reports, log and audit records | `#B38A00` | `#6F5600` | `#FAF3DA` |
| External system: STUN servers, an ACME CA, a VPN or tunnel provider, an identity provider | `#5E43A8` | `#4B3592` | `#EEEAF7` |
| Substrate: the host and its kernel, a VM, a cluster, a bridge host, netlink, nftables | `#C9620F` | `#A44E07` | `#FBEFE3` |
| Refusal, error exit, failed state | `#C6343C` | `#A3262E` | `#F8E8E9` |
| Frame, anything without a role | `#7D8794` | `#2B3440` | `#EEF0F3` |

### Notation legend

![The notation of the figures: the colours of the roles; the shapes for components, stores, messages, actors, frames, planned parts and tables; the twelve kinds of arrows; the elements of a state machine; and step badges, lifelines and notes.](../../diagrams/conventions-legend.svg)

### Notation

| Element | Meaning | Looks like | Helper |
| --- | --- | --- | --- |
| Component | A service, a package, a process, a participant | Rounded box, outline in the role colour, bold name | `box` |
| Component, set apart | The component a figure is about | The same box filled with the role colour | `filled` |
| Tile | One short name in a row of many | The same box with narrow padding | `tile` |
| Store | A data directory, a cache, a file, a database | Cylinder in the role colour | `store` |
| Message or document | A response, a request body, a document | Sheet with a folded corner | `sheet` |
| Outside actor | An operator, a user, a browser | Dark outlined box | `actor` |
| Frame | A binary, a host, a cluster, a scope, an arm of a state machine | Large light frame with a bold title and an optional dark chip | `frame` |
| Planned part | Designed, not built | Dashed box with a `not built` chip | `dashedBox`, `chip` |
| Table or record | The fields of a wire message, a table | Box with a header and one row per field | `table`, `record` |
| State | A state of a state machine, a step of a pipeline | Box with slightly rounded corners, dark outline | `state` |
| Terminal, sticky | A state the machine never leaves | The state with a `terminal` or `sticky` chip, or followed by the final marker | `chipOn`, `final` |
| Sink | A state left only by an intervention, or kept forever | The state in grey | `state(stateSink, …)` |
| Failed state, refusal | A failure, an error response | The state in red | `state(stateFailed, …)` |
| Initial and final marker | Where a machine starts and ends | A dark dot; a ring around a dot | `dot`, `final` |
| Self-transition | A transition back into the same state | A loop on the right of the state | `loop` |
| Step badge | Step n of a flow the page describes | Dark circle with a light number at the tail of an arrow or on a box | `badge` |
| Note | A remark on a box | Grey panel joined to the box by a thin line | `notePanel` |
| Order, transition | What comes first points at what follows | Dark arrow | `flow` |
| Call | A request across a process or network boundary | Blue arrow | `call` |
| Reply | The answer to a call | Dashed dark arrow with an open head | `reply` |
| Event, record | An event or a record on its way | Ochre arrow | `publish` |
| Secret material | A secret value travels in the arrow's direction | Magenta arrow | `secretFlow` |
| Creates | plexd or the control plane creates or provisions what the arrow points at | Green arrow | `creates` |
| Out of band | A hand-off a person makes outside plexd and the control plane | Dashed dark arrow | `outOfBand` |
| Planned path | Designed, not built | Dashed grey arrow | `planned` |
| Refusal | The exit to an error | Red arrow | `refuse` |
| Derived | A relation that holds at run time without being stored | Dotted grey arrow | `derived` |
| Relation | A mount, membership, an association | Grey line without a head | `relation` |
| Traffic | Traffic in both directions | Green line with a head at each end | `both` |

A sequence diagram is drawn with `sequence` in `seq.go`: participants
across the top, a lifeline under each, and one message per row with
`msg`, `self` and `note`.
