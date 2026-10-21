---
description: "One-time links that carry secrets either way: ask someone for a secret, or share one. The other person needs no account, and the values are encrypted in the browser."
---

# Secrets by link

A drop is a one-time link that carries secrets, in either direction: ask
someone for a secret, or share one with them. The other person doesn't need
an account, and Sprott only ever holds ciphertext.

## Ask someone for a secret

Sometimes the key you need is with someone else: a teammate outside your
vault, a client, a friend. Send them a link. They paste what they have, and
it arrives in your vault for you to review.

1. On the vault's **Raw secrets** tab, click **Request by link**.
2. Optionally list the key names you need (`STRIPE_KEY, STRIPE_WEBHOOK_SECRET`),
   add a note they will see, and choose how long the link stays open:
   1 hour, 24 hours (the default) or 7 days.
3. Click **Copy & done** and send the link in a chat you already use with
   them.

Not sure what they have? Leave the key names empty. They can paste a whole
`.env`, some JSON or a few lines of notes, and you sort it out when it
arrives. Until they send, the link waits at the top of Raw secrets, where
you can copy it again or **Revoke** it.

**What they see.** A page that names who is asking, from the name and email
on your Sprott account, and shows your note. They fill in the rows you asked
for, add their own, or paste anything. One click encrypts it and sends it,
and the link stops working.

**When it arrives.** It shows at the top of Raw secrets. **Review** opens it
in the same **Import from .env** sheet you use for any paste: keep what you
need, rename, then **Add to draft** and **Encrypt & save**. Nothing reaches
your vault until you save. **Delete the drop after saving** is ticked by
default; untick it to review it again later. Either way it is deleted 7 days
after it arrived. **Discard** deletes it now.

## Share a secret

1. On **Raw secrets**, select the secrets and click **Share by link** next
   to **Delete selected**.
2. Optionally add a note and choose how long the link stays open.
3. **Add a code to send separately** is ticked by default. Leave it on: the
   link alone can't open the share, so chat previews and forwarded messages
   give nothing away.
4. Click **Create link**. The link and the code are shown here only, once.
   Copy the link, then the code, and send them in two places: the link in
   chat, the code by text or in person. **Copy both & done** puts them in one
   message when that is good enough.

The other person opens the link, enters the code and clicks **Show secrets**.
They can copy each value, copy them all as `.env`, or download a `.env`. The
values are shown only that once: refreshing or closing the page clears them.

On Raw secrets the share shows as waiting until it is opened, then as
**Opened**. [Activity](activity.md) records who shared how many secrets and
when the share was opened, never the key names. If someone tells you the
link was already used and it wasn't them, someone else opened it first:
rotate those secrets.

A share carries the saved values. An edit you haven't saved isn't shared.

## How it's protected

- **Asking.** The link carries your public encryption key after the `#`,
  which browsers never send to a server. The sender's browser encrypts
  everything to that key before anything leaves (HPKE: X25519, HKDF-SHA256,
  ChaCha20-Poly1305). Only you can open it, with the identity key your
  passkey unlocks; other members of a shared vault cannot. The ciphertext is
  bound to its link, so it can't be moved into another one.
- **Sharing.** The link's `#` part and the code are two halves of the key
  (HKDF-SHA256, then AES-256-GCM); your browser encrypts the values before
  uploading them. Sprott stores neither the link nor the code. To refuse a
  wrong code without opening anything it keeps a check value derived from
  both, and five wrong codes delete the share. Opening hands the ciphertext
  over once and deletes it. A chat app loading the link for a preview
  doesn't count: only the **Show secrets** click does.
- Every link takes one use, expires on schedule, and can be revoked.

Your note, the key names you ask for and the number of secrets you share are
not encrypted: the page shows them to whoever has the link.

Got one of these links without expecting it? Check with the person named on
the page before you send or open anything.
