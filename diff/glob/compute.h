/* glob: shell-style pattern matching (glob_match) -- a backtracking matcher
 * with '*' wildcards, '?', and '[...]' classes. Deterministic (pat,str) ->
 * bool; a control-flow-heavy codegen shape unlike the arithmetic targets.
 *
 * Strings are tiny (4 chars) and NUL-terminated: glob's '*' backtracking is
 * worst-case exponential (see the comment in lib/glob.c), and even 8-char
 * symbolic inputs blow the verifier's 1M-insn budget. 4 chars keeps the
 * explored state space bounded while still driving wildcard/class paths (the
 * seeded bytes fold into an alphabet that includes the metacharacters). */
static __u64 diff_compute(const __u64 in[4])
{
	static const char alpha[8] = { 'a', 'b', 'c', '*', '?', '[', ']', 'a' };
	char pat[5], str[5];
	int i;

	for (i = 0; i < 4; i++) {
		pat[i] = alpha[(in[0] >> (i * 8)) & 7];
		str[i] = alpha[(in[1] >> (i * 8)) & 7];
	}
	pat[4] = '\0';
	str[4] = '\0';

	return glob_match(pat, str) ? 1 : 0;
}
