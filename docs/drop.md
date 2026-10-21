---
description: "Ask someone for secrets with a one-time link. They need no account; what they send is encrypted in their browser, and only you can open it."
---

# Ask someone for a secret

Sometimes the key you need is with someone else: a teammate outside your
vault, a client, a friend. Send them a one-time link. They paste what they
have, and it arrives in your vault for you to review. They don't need an
account.

## Send a link

1. On the vault's **Raw secrets** tab, click **Request by link**.
2. Optionally list the key names you need (`STRIPE_KEY, STRIPE_WEBHOOK_SECRET`),
   add a note they will see, and choose how long the link stays open:
   1 hour, 24 hours (the default) or 7 days.
3. Click **Create link** and send it in a chat you already use with them.

Not sure what they have? Leave the key names empty. They can paste a whole
`.env`, some JSON or a few lines of notes, and you sort it out when it
arrives.

Until they send, the link waits at the top of Raw secrets. You can copy it
again or **Revoke** it there.

## What they see

A page that names who is asking, from the name and email on your Sprott
account, and shows your note. They fill in the rows you asked for, add their
own, or paste anything. One click encrypts it and sends it, and the link
stops working.

Got one of these links without expecting it? Check with the person named on
the page before you send anything.

## When it arrives

It shows at the top of Raw secrets. **Review** opens it in the same
**Import from .env** sheet you use for any paste: keep what you need, rename,
then **Add to draft** and **Encrypt & save**. Nothing reaches your vault
until you save.

**Delete the drop after saving** is ticked by default. Untick it to keep the
delivery and review it again later. Either way it is deleted 7 days after it
arrived. **Discard** deletes it now.

## How it's protected

- The link carries your public encryption key after the `#`. Browsers never
  send that part of a link to a server.
- The sender's browser encrypts everything to that key before anything
  leaves (HPKE: X25519, HKDF-SHA256, ChaCha20-Poly1305). Sprott stores only
  the ciphertext and cannot read it.
- Only you can open it, with the identity key your passkey unlocks. Other
  members of a shared vault cannot.
- The ciphertext is bound to its link, so it can't be moved into another
  one.
- A link takes one submission, expires on schedule, and can be revoked.

Your note and the key names you ask for are not encrypted: the page shows
them to whoever has the link.
