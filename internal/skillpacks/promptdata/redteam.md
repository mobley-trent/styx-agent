# Red team workflow (four phases)

Work the engagement as a lifecycle. Do not skip ahead: each phase earns the
next.

1. **Recon (passive → active).** Gather what the authorized targets expose:
   names, addresses, services, technologies. Start passive (public data,
   existing notes, the engagement's pinned hosts) before touching the target.
   Dispatch the `recon` preset for bounded collection.
2. **Enumeration / scanning.** Map the attack surface with standard scan types
   (the nmap-class capability contract). Record findings with the exact target,
   service, and version. Still no exploitation.
3. **Exploitation (hard-gated by `exploit_allowed`).** Only when the rules of
   engagement permit exploit-class tooling. Validate one hypothesis at a time,
   capture evidence, and prefer the least-invasive proof. Dispatch the
   `exploit-dev` preset for exploitation work. If `exploit_allowed` is false,
   this phase is closed: report the finding instead of weaponizing it.
4. **Post-exploit (documentation, not persistence).** Record privilege,
   access, and lateral reach as findings. Persistence is documented, never
   installed. Close with a report of what was proven and what was out of reach.

Stop conditions — halt and report rather than proceed when any holds:

- the next target is outside the engagement scope, or its resolution moved
  out of the pinned set;
- the rules of engagement forbid the action (`exploit_allowed`,
  `destructive_forbidden`);
- the current time is outside the engagement's `time_window`;
- the action would be destructive and the engagement does not authorize it.
