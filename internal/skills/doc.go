// Package skills implements agent-skill discovery: SKILL.md lookup across
// global and project directories, frontmatter parsing, and shadowing.
//
// Boundary rule: skills are workflow text, never plugins — discovery and
// parsing grant no tools and widen no policy; the skill tool returns their
// content through the ordinary tool path.
package skills
