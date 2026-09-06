# LinkedIn assets

Quick links for posting:

- **Flashy HTML (this repo):** [`docs/one-pager.html`](one-pager.html)
- **Public deck:** a coordinator may later publish `mcp-atsa-admission-deck`. Until then, screenshot the HTML above.
- **Engineer notes:** [`docs/LINKEDIN-NOTES.md`](LINKEDIN-NOTES.md)

---

# LinkedIn post (copy-paste ready)

Use this as a single post, or split the **Carousel** section into slides.

---

## Post

Your MCP host takes a tool server on faith.

TLS says you reached the named endpoint.
OAuth says the user may use this server.

Nobody asks the third question: is this server one the *host* is authorized to use as a tool provider — and which tools?

That’s the gap. A prompt-injected model can drive a destructive tool on any server the host already connected to.

I built a tiny fix: check the server at the door.

ATSA — Attested Tool-Server Admission, draft SEP-2809.
CPU only. No GPU. No TPM. No Keycloak.

What it does:
→ Load a small signed clearance a server would publish at a well-known URI
→ Verify it against a pinned trust root (Ed25519)
→ Admit or deny *before* any tool dispatch
→ Keep a separate per-server tool allow-list — admitting a server ≠ authorizing every tool
→ Append-only audit log of every decision

Plain language, three layers:

OAuth = badge. The user is allowed in the building.
ATSA = door check. Is this the server the host is allowed to treat as a tool provider?
ACLE paper (arXiv:2609.02690) = sticky note on each risky call. After OAuth, re-check the real server and the exact action. Same neighborhood, stricter timing. We cite it. We do not implement the leases.

Official MCP today = OAuth.
ATSA = draft SEP, not shipped.
ACLE = research paper, not an official MCP standard.

Weekend sample. Private repo. Tests green.

If you run MCP at work and you only check TLS + OAuth, you never asked the door question.

#AISecurity #MCP #AgentSecurity #LLMOps

---

## Carousel (6 slides — paste one slide per card)

**Slide 1 — Hook**
Check the MCP tool server at the door.

TLS reached the endpoint.
OAuth issued a badge.
Nobody asked if this server is allowed to be a tool provider.

**Slide 2 — The missing question**
Hosts today take `tools/list` on faith.

A prompt-injected model can drive a destructive tool
on any server the host already connected to.

**Slide 3 — Three layers**
OAuth = badge.
ATSA = door check (draft SEP-2809).
ACLE paper = sticky note on each risky call
(arXiv:2609.02690).

Same neighborhood. Different timing.

**Slide 4 — The fix**
A host-side admission gate.

Load a signed clearance.
Verify it against a pinned trust root.
Admit or deny — with reasons you can read.

**Slide 5 — What it checks**
• Ed25519 signature vs pinned trust root
• Expiry + expected server id
• Separate tool allow-list
• Append-only audit of admit / deny

CPU only. No TPM. No Keycloak.

**Slide 6 — CTA**
Don’t dispatch until the server clears the door.

ATSA is the connect-time check.
ACLE is the per-call sticky note (not built here).

(Private sample: mcp-atsa-admission)

---

## Comment you can pin under the post

Built as a weekend host-side door check inspired by draft SEP-2809 (ATSA).
Not a full SEP port. Not ACLE-MCP leases (arXiv:2609.02690). Official MCP today is still OAuth.

Happy to walk through the admit / deny JSON if useful.
