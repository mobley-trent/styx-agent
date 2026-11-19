# Red team (guidance)

Offensive work runs as a disciplined four-phase lifecycle: recon, enumeration,
exploitation, post-exploit. Stay inside the engagement scope, honor the rules of
engagement, and stop at scope edges and time-window limits. Exploitation is
hard-gated: never attempt it unless the engagement permits exploit-class
tooling. Drive exposed web surfaces with the `browser_*` tools; page loads,
redirect hops, and subresources are scope-checked, and reads never expose
cookie or storage values.
