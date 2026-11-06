---
id: SF-53
status: done
severity: low
effort: S
area: Network language
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-53 A comment in the network language can hold text-direction and zero-width characters

**Low** · S · Network language · Proven · part of [[Audit 2026-11-05]]

## What exists
`rostranspiler.COMMENT` lets a comment (and a `log-prefix`) hold any character except ASCII controls and a few shell and RouterOS metacharacters. The line and paragraph separators and NEL are stopped, but only because the tokenizer treats them as spaces and refuses the statement. Bidirectional controls (U+202A to U+202E, U+2066 to U+2069) and zero-width characters (U+200B to U+200F, U+2060, U+FEFF) pass, and come out unchanged in the RouterOS, nftables, iptables, ufw and OpenWrt output.

## Evidence
`rostranspiler.py:19`, the pattern. Run: `parse('/ip firewall filter add chain=input action=accept comment="ok\u202ex"')` was accepted, and `emit` for those five targets kept the character. The same with U+2066 and U+200B. U+0085, U+2028, U+2029, U+000B, U+000C and U+001C were refused with the odd message `'"ok' is not name=value`.

## Why it matters
Compiled output is what a person reads before they apply it to a firewall. A right-to-left override in a comment can make an address in it read reversed, or hide where the comment ends. It changes nothing a rule does, and the person who writes it can already write the rule. So it is Low: a review aid that can be fooled, and a refusal message that does not say why.

## Suggested approach
Refuse bidirectional controls and zero-width characters in `COMMENT`, and in `NAME` if it is ever loosened, and say so in the message instead of the tokenizer's.

## Done when
- [x] A comment with any of those characters is refused, with a message that names the character
- [x] A test lists them, so a new one cannot be added to the allowed set unseen
- [x] The commit is written here

## Fixed
2026-11-05, in `b7c34bd`. `rostranspiler._comment` refuses U+200B to U+200F, U+2028, U+2029, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069 and U+FEFF with "holds a text-direction or zero-width character", before the old pattern is tried, so the message names the cause. Letters of other scripts (Hebrew, Arabic, accented Latin) are still allowed. A line separator is refused earlier still, because the tokenizer cuts the statement at it. Test: `test_a_comment_can_not_hold_a_character_that_changes_how_it_reads`. Not lab-tested.
