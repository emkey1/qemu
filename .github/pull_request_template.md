<!--
Thanks for the contribution. The fork is a series of commits on upstream QEMU, rebased onto each
release, so each commit should stand on its own and say why it is there.
-->

## Description

<!-- What the change does and why. Mention if it fixes an issue using `Closes #123`. -->

## How the Change Was Verified

<!--
What CI checks is rarely sufficient, so please describe what you did to verify the correctness of
the change yourself.
-->

- [ ] CI passes
- [ ] Exercised beyond CI, under (TCTI, the JIT or both), on (a Mac or a device, and which):
- [ ] Timed, if the change is meant to be faster or touches a hot path, with the numbers in the
      commit message (ideally from tctiSH's benchmarking harness)

### Tests

- [ ] A test in `tests/tcg/` covers the change, or this section says why it can't
- [ ] If it's a fix, the new test fails without said fix

### Commits

- [ ] Each commit builds and passes on its own, and the branch is rebased onto `tctish-edition`
      with no merge commits
- [ ] Subjects take QEMU's `subsystem: summary` form, and messages include the why of it
- [ ] US spelling is used, in code, comments and messages
- [ ] If `tcti-gadget-gen.py` changes the gadgets, the commit message gives the count and size it
      prints

### Upstream

<!-- Does upstream QEMU have the same problem? Do you mean to upstream this to qemu-devel? -->

### Anything Else

<!--
Things you want the reviewer to know such as any trade-offs you made, things you were unsure about,
things you would like looked at closely, and so on.
-->
