package browser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Read bounds (§3.4): a read is one page's text, not a document dump.
const (
	// DefaultMaxChars is what `browser_read` returns when the model names no
	// bound.
	DefaultMaxChars = 8192
	// MaxChars is the hard cap, whatever the model asks for.
	MaxChars = 32768
	// maxNameRunes bounds one node's name, so one enormous text node cannot
	// crowd out the rest of the tree.
	maxNameRunes = 200
	// maxSnapshotNodes bounds the DOM walk. A page with more accessible nodes
	// than this is read from the top; the truncation line says so.
	maxSnapshotNodes = 500
	// maxIndentDepth bounds tree indentation.
	maxIndentDepth = 12
)

// rawNode is one node the collection script reported. It carries no value
// field: a read returns names, roles, and flags, never a form or storage value
// (§3.6).
type rawNode struct {
	Parent      int    `json:"parent"`
	Role        string `json:"role"`
	Name        string `json:"name"`
	Index       int    `json:"index"`
	Interactive bool   `json:"interactive"`
	Disabled    bool   `json:"disabled"`
	Checked     *bool  `json:"checked,omitempty"`
	Level       int    `json:"level,omitempty"`
}

// rawSnapshot is the collection script's result.
type rawSnapshot struct {
	URL   string    `json:"url"`
	Title string    `json:"title"`
	Nodes []rawNode `json:"nodes"`
}

// Handle is one addressable node from the latest snapshot. Handles are assigned
// per snapshot, in tree order: the model can only address an element it read,
// and a handle from an earlier snapshot is refused rather than guessed at
// (§3.2).
type Handle struct {
	Number int
	Index  int
	Role   string
	Name   string
}

// snapshot is the driver's current view of the page, with its handle registry.
type snapshot struct {
	URL     string
	Title   string
	Nodes   []rawNode
	Handles map[string]Handle
}

// newSnapshot builds a snapshot and its per-snapshot handles. Only interactive
// nodes take a number; text and structure keep the aria shape without becoming
// clickable.
func newSnapshot(raw rawSnapshot) *snapshot {
	s := &snapshot{
		URL:     raw.URL,
		Title:   raw.Title,
		Nodes:   raw.Nodes,
		Handles: map[string]Handle{},
	}
	children := childIndex(raw.Nodes)
	next := 0
	var walk func(int, int)
	walk = func(index, depth int) {
		if index < 0 || index >= len(raw.Nodes) || depth > maxIndentDepth {
			return
		}
		node := raw.Nodes[index]
		if node.Interactive {
			next++
			s.Handles[strconv.Itoa(next)] = Handle{
				Number: next,
				Index:  index,
				Role:   node.Role,
				Name:   cleanName(node.Name),
			}
		}
		for _, child := range children[index] {
			walk(child, depth+1)
		}
	}
	for _, root := range children[-1] {
		walk(root, 0)
	}
	return s
}

// childIndex groups node indexes by parent. Nodes whose parent is unknown or
// points forward are treated as roots rather than dropped: a page element the
// script could not place is still visible to the reader.
func childIndex(nodes []rawNode) map[int][]int {
	children := map[int][]int{}
	for i, node := range nodes {
		parent := node.Parent
		if parent < 0 || parent >= len(nodes) || parent >= i {
			parent = -1
		}
		children[parent] = append(children[parent], i)
	}
	return children
}

// lookup resolves a model-supplied handle against the latest snapshot.
func (s *snapshot) lookup(handle string) (Handle, error) {
	key := strings.TrimSpace(handle)
	if key == "" {
		return Handle{}, fmt.Errorf("%w: no handle was given; take a fresh snapshot with browser_read", ErrStaleHandle)
	}
	found, ok := s.Handles[key]
	if !ok {
		return Handle{}, fmt.Errorf("%w %q: the current snapshot does not expose it; take a fresh snapshot with browser_read",
			ErrStaleHandle, key)
	}
	return found, nil
}

// render returns the whole page as a bounded aria snapshot (§3.2, §3.4).
func (s *snapshot) render(maxChars int) string {
	var b strings.Builder
	if s.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", s.URL)
	}
	if s.Title != "" {
		fmt.Fprintf(&b, "Title: %s\n", s.Title)
	}
	if s.URL != "" || s.Title != "" {
		b.WriteString("\n")
	}
	if len(s.Nodes) == 0 {
		b.WriteString("(no accessible nodes)\n")
	} else {
		s.renderNodes(&b, -1, 0, map[int]bool{})
	}
	if len(s.Nodes) >= maxSnapshotNodes {
		b.WriteString("[browser_read: the page exposed more than 500 nodes; only the first 500 were read]\n")
	}
	return truncate(b.String(), maxChars)
}

// renderSubtree returns one element and its children (§3.4).
func (s *snapshot) renderSubtree(handle Handle, maxChars int) string {
	var b strings.Builder
	node := s.Nodes[handle.Index]
	fmt.Fprintf(&b, "[%d] %s %q\n", handle.Number, node.Role, cleanName(node.Name))
	children := childIndex(s.Nodes)
	for _, child := range children[handle.Index] {
		s.renderNode(&b, children, child, 1, map[int]bool{})
	}
	return truncate(b.String(), maxChars)
}

// renderNodes renders every root of the page.
func (s *snapshot) renderNodes(b *strings.Builder, parent, depth int, seen map[int]bool) {
	for _, child := range childIndex(s.Nodes)[parent] {
		s.renderNode(b, childIndex(s.Nodes), child, depth, seen)
	}
}

// renderNode renders one node and its descendants, in tree order, with its
// handle when it is interactive.
func (s *snapshot) renderNode(b *strings.Builder, children map[int][]int, index, depth int, seen map[int]bool) {
	if index < 0 || index >= len(s.Nodes) || seen[index] || depth > maxIndentDepth {
		return
	}
	seen[index] = true
	node := s.Nodes[index]

	indent := strings.Repeat("  ", depth)
	switch {
	case node.Interactive:
		handle := s.handleFor(index)
		if handle > 0 {
			fmt.Fprintf(b, "%s[%d] %s", indent, handle, node.Role)
		} else {
			fmt.Fprintf(b, "%s- %s", indent, node.Role)
		}
	default:
		fmt.Fprintf(b, "%s- %s", indent, node.Role)
	}
	if name := cleanName(node.Name); name != "" {
		fmt.Fprintf(b, " %q", name)
	}
	if node.Level > 0 {
		fmt.Fprintf(b, " [level=%d]", node.Level)
	}
	if node.Disabled {
		b.WriteString(" [disabled]")
	}
	if node.Checked != nil {
		if *node.Checked {
			b.WriteString(" [checked]")
		} else {
			b.WriteString(" [unchecked]")
		}
	}
	b.WriteString("\n")

	for _, child := range children[index] {
		s.renderNode(b, children, child, depth+1, seen)
	}
}

// handleFor returns a node's handle number, 0 when the node is not
// interactive.
func (s *snapshot) handleFor(index int) int {
	for number, handle := range s.Handles {
		if handle.Index == index {
			n, _ := strconv.Atoi(number)
			return n
		}
	}
	return 0
}

// cleanName collapses a node's name to one readable line.
func cleanName(raw string) string {
	var b strings.Builder
	space := false
	count := 0
	for _, r := range strings.ToValidUTF8(raw, "") {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		if count >= maxNameRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}

// truncate bounds text at maxChars and says so explicitly (§3.4).
func truncate(text string, maxChars int) string {
	limit := maxChars
	if limit <= 0 {
		limit = DefaultMaxChars
	}
	if limit > MaxChars {
		limit = MaxChars
	}
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8Start(text[cut]) {
		cut--
	}
	return text[:cut] + fmt.Sprintf("\n[browser_read: truncated at %d characters]", limit)
}

// utf8Start reports whether b begins a UTF-8 rune.
func utf8Start(b byte) bool { return b&0xc0 != 0x80 }

// collectScript is the page-side aria walk. It reports roles, names, and
// interactive flags, marks each interactive element with a per-snapshot index,
// and never reads a value, a cookie, or a storage area (§3.6). It clears the
// previous snapshot's markers first, so a re-read never addresses an element
// the model did not just see.
const collectScript = `/*styx:read*/ (() => {
  const INTERACTIVE = new Set(['link','button','textbox','checkbox','radio','combobox','listbox','option',
    'menuitem','menuitemcheckbox','menuitemradio','tab','searchbox','switch','slider','spinbutton']);
  const TAG_ROLES = {
    a: 'link', button: 'button', textarea: 'textbox', select: 'combobox',
    h1: 'heading', h2: 'heading', h3: 'heading', h4: 'heading', h5: 'heading', h6: 'heading',
    img: 'img', nav: 'navigation', main: 'main', header: 'banner', footer: 'contentinfo',
    form: 'form', table: 'table', ul: 'list', ol: 'list', li: 'listitem', p: 'paragraph'
  };
  const SKIP = new Set(['script','style','noscript','template','svg','head','meta','link']);
  for (const old of document.querySelectorAll('[data-styx-index]')) old.removeAttribute('data-styx-index');

  const roleOf = (el) => {
    const explicit = (el.getAttribute('role') || '').trim().toLowerCase();
    if (explicit) return explicit;
    const tag = el.tagName.toLowerCase();
    if (tag === 'input') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      if (type === 'submit' || type === 'button' || type === 'reset' || type === 'image') return 'button';
      if (type === 'search') return 'searchbox';
      if (type === 'hidden') return '';
      return 'textbox';
    }
    return TAG_ROLES[tag] || '';
  };

  const nameOf = (el) => {
    const tag = el.tagName.toLowerCase();
    const labelled = el.getAttribute('aria-labelledby');
    if (labelled) {
      const parts = labelled.split(/\s+/).map((id) => {
        const target = document.getElementById(id);
        return target ? (target.innerText || '') : '';
      }).filter(Boolean);
      if (parts.length) return parts.join(' ');
    }
    const aria = el.getAttribute('aria-label');
    if (aria) return aria;
    if (el.id) {
      try {
        const label = document.querySelector('label[for="' + el.id.replace(/"/g, '\\"') + '"]');
        if (label && label.innerText) return label.innerText;
      } catch (e) {}
    }
    const wrapping = el.closest ? el.closest('label') : null;
    if (wrapping && wrapping.innerText) return wrapping.innerText;
    if (el.getAttribute('alt')) return el.getAttribute('alt');
    if (el.getAttribute('placeholder')) return el.getAttribute('placeholder');
    if (el.getAttribute('title')) return el.getAttribute('title');
    // A textarea's innerText is its content: a typed secret would otherwise
    // reappear in a snapshot. Fields are named by their label, never value.
    if (tag === 'textarea' || tag === 'input' || tag === 'select') return '';
    return el.innerText || '';
  };

  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
  };

  const nodes = [];
  let next = 0;
  const walk = (el, parent) => {
    if (!el || nodes.length >= 500) return;
    const tag = el.tagName ? el.tagName.toLowerCase() : '';
    if (SKIP.has(tag)) return;
    let index = -1;
    const role = roleOf(el);
    if (role) {
      const interactive = INTERACTIVE.has(role);
      const name = nameOf(el);
      if ((interactive || name) && visible(el)) {
        const node = { parent: parent, role: role, name: name, interactive: interactive };
        if (interactive) {
          el.setAttribute('data-styx-index', String(next));
          node.index = next;
          next++;
        }
        if (el.disabled) node.disabled = true;
        if (role === 'checkbox' || role === 'radio') node.checked = !!el.checked;
        if (role === 'heading') node.level = Number(tag.charAt(1)) || 0;
        index = nodes.length;
        nodes.push(node);
      }
    }
    const childParent = index >= 0 ? index : parent;
    const children = el.children || [];
    for (let i = 0; i < children.length; i++) walk(children[i], childParent);
  };

  walk(document.body || document.documentElement, -1);
  return JSON.stringify({ url: location.href, title: document.title, nodes: nodes });
})()`

// evaluateOutcome is the shape every page-side script returns for an action:
// whether it found and could act on the element.
type evaluateOutcome struct {
	OK      bool `json:"ok"`
	Missing bool `json:"missing"`
	Blocked bool `json:"blocked"`
}

// parseOutcome decodes an action script's result.
func parseOutcome(raw string) (evaluateOutcome, error) {
	var outcome evaluateOutcome
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		return evaluateOutcome{}, fmt.Errorf("browser: decode the page's answer: %w", err)
	}
	return outcome, nil
}
