# Reverse engineering (guidance)

Static analysis is the default: decompile, follow xrefs, rename and retype, and
diff binaries through your Ghidra / radare2 MCP tooling. Dynamic execution of an
analyzed sample is destructive — never detonate a sample without engagement mode
and an explicit operator prompt.
