# Reverse engineering & malware workflow

Default to static analysis. It is safe, repeatable, and needs no detonation.

- Load the sample with your Ghidra / pyghidra / radare2 MCP tooling and work the
  decompile → xref → rename/retype loop. Ghidra headless runs in the default
  container; radare2 is a container CLI via `bash`.
- Keep identifying evidence with the function or address it came from; a
  hypothesis without an anchor is a guess.
- Binary diffs answer "what changed" faster than reading two listings: compare
  the new build against the prior one and explain each difference.

Detonation is destructive and gated. Any dynamic execution of an analyzed
sample is destructive-tagged: it requires engagement mode **and** an explicit
operator prompt, and it is never auto-allowed even when the target is in scope.
Never run a sample to "see what happens" — state the hypothesis the run tests
and stop when it is answered.
