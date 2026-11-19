// Package apispec implements `api_spec_load` (docs/api-spec-targets.md, #159,
// ADR-0014): the harness-owned tool that turns one OpenAPI, Swagger, or
// Postman document into the declared surface a run can see.
//
// The shape is fixed by the contract:
//
//	document bytes → format sniff → declared servers and operations
//	  → scope check at load → one host upsert per usable server, tagged `declared`
//	  → a bounded receipt plus a derived inventory artifact
//
// Three properties are structural rather than conventional:
//
//   - **A declaration is a fact source, never an authorization source.** A
//     declared server is usable only when every address it resolves to already
//     falls inside the engagement's pool. An out-of-scope server is refused by
//     name, with the pool it missed in the reason; there is no prompt, no flag,
//     and no code path that adds a target (docs/spec.md §6.1, §7.1).
//   - **A load writes hosts and nothing else.** A declared port was never
//     observed, so it becomes no service; an endpoint is a claim, so it becomes
//     no finding, credential, or edge, and no evidence (ADR-0014).
//   - **Requirements in, values never.** The receipt and inventory carry a
//     security scheme's name, type, and location — never a header value, token,
//     cookie, or variable value. A literal credential in the document is
//     counted, never echoed or truncated (§4.3).
//
// The document is named by the call's `path` and confined to the workspace;
// there is no tree scan and no config key (§2.2). A load is not a parser: it
// neither raises nor clears a pending-parse obligation, because it reads a
// reviewed declaration rather than scanner output, and the inventory it writes
// under `.styx/out/api/` is a derived rendering nothing cites as evidence.
package apispec
