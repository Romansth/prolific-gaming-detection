# Report design

Why the report looks the way it does, and what is still open.

## Only strong signs flag

The screen checks 23 signs. Six are strong: when one of them fires, gaming is more likely than
not. A participant is flagged when at least one strong sign fires.

| Code | Strong sign |
|---|---|
| M1 | A second Prolific id used in the monitored browser |
| M2 | Two enrolled participants in one running browser |
| M3 | An antidetect browser |
| M4 | Google sign-ins routed outside the US on two days at least a week apart |
| M5 | A non-US device clock on 7 or more days, or half the time |
| M6 | Chrome installed with a non-US locale |

The other 17 are weak on their own. Each has an ordinary explanation that is often true, like a
shared family PC, a night shift or a trip abroad. They appear on a flagged participant's card as
context, and in a collapsed list for everyone else. The CSV keeps all 23.

On the synthetic test pull this flags 10 of 42 participants. Flagging on any sign would list 29.

Two weak signs may deserve to flag:

- **m12**: the same mail address or display name under two Prolific ids (raw data only).
- **m2**: another participant's Prolific id synced into this browser from another device on the
  same Google account.

To promote one, change its tier from `minor` to `major` in `fraudscreen/signs/__init__.py`.

## The shareable copy

The token copy is built from the report's data, not by editing the team's HTML. Every string goes
through the redactor's rules with the same key used for the data, and the page is rendered again.
Before the copy is written, the redactor's separate leak checker looks for real ids and e-mail
addresses. If it finds any, the run stops and only the team copy exists.

## Check on the first real pull

1. **How often device records are written.** M2 links two participants only when the same browser
   id shows up within one minute. If records come every five minutes, widen the window
   (`_same_minute` in `fraudscreen/signs/machine.py`).
2. **Whether completion URLs carry a session id.** Without it, the study windows behind m15 run to
   their 90-minute cap.
3. **How many participants have no device records.** If this is routinely above 10%, the yellow box
   will show every week. Raise the threshold in `_warnings` in `fraudscreen/report.py`.
