---
description: "Sprott Drop moves secrets through a one-time link, in either direction, to people with or without a Sprott account. Values are encrypted in the browser; Sprott relays only ciphertext."
---

# Sprott Drop: secrets by one-time link

Sprott Drop moves secrets between a Sprott vault and anyone else through a
single-use link. The other side needs no account and installs nothing. The
values are encrypted in the browser before they leave it, and Sprott's
servers only ever relay ciphertext.

It works in both directions:

- **Request.** A vault member asks someone for a key, a token or a whole
  `.env`. What comes back lands in the vault for review before anything is
  saved.
- **Share.** A vault member sends saved secrets to someone. The recipient
  sees them once.

## How it works

| | Request | Share |
|---|---|---|
| Encrypted where | In the sender's browser, to the requester's public key | In the sharer's browser, with a key split between the link and a code |
| Who can open it | Only the requester, with the identity key their passkey unlocks | Only someone holding both the link and the code |
| Uses | One submission | One opening |
| Expires | 1 hour, 24 hours or 7 days; revocable at any time | Same |
| What Sprott stores | Ciphertext, until it is saved or for at most 7 days | Ciphertext, until it is opened |

**Encryption in the browser.** The part of a Drop link after the `#` never
reaches a server; browsers keep it on the device.

- A request link carries the requester's public encryption key there. The
  sender's browser encrypts everything to that key (HPKE: X25519,
  HKDF-SHA256, ChaCha20-Poly1305) and binds it to that one link. Other
  members of a shared vault cannot open it.
- A share link carries half of a key there; the other half is a 10-character
  code sent separately, which is on by default. Together they derive the
  decryption key (HKDF-SHA256, AES-256-GCM). The link alone opens nothing,
  so chat previews and forwarded messages give nothing away.

**Single use.** A request link accepts one submission. A share opens once:
the recipient's **Show secrets** click makes the server hand over the
ciphertext and delete it in the same step. Opening the link, including a
chat app loading it for a preview, does not count. To refuse a wrong code
without opening anything, Sprott keeps a check value derived from both
halves; five wrong codes delete the share.

**A named sender.** Every Drop page shows the name and email of the Sprott
account behind the link, never free text. A note added by that person is
shown separately and labelled as theirs.

**Recorded.** [Activity](activity.md) records who shared how many secrets and
when a share was opened. It never records key names or values.

**Not encrypted:** the note, the key names a request asks for, and the number
of secrets in a share. The page shows them to whoever has the link.

## Request secrets

1. On the vault's **Raw secrets** tab, click **Request by link**.
2. Optionally list the key names needed (`STRIPE_KEY, STRIPE_WEBHOOK_SECRET`)
   and add a note. Choose how long the link stays open.
3. Click **Copy & done** and send the link over a channel the other person
   already uses.

Without key names, the page offers a single box for pasting a `.env`, some
JSON or a few lines of notes. With key names, it offers one row per name; a
named row must be filled in or removed before sending.

The waiting link shows at the top of Raw secrets, where it can be copied
again or revoked. When the delivery arrives, **Review** opens it in the
**Import from .env** sheet: keep what is needed, rename, **Add to draft**,
then **Encrypt & save**. Nothing reaches the vault before the save.
**Delete the drop after saving** is ticked by default. A delivery is deleted
7 days after it arrives either way, and **Discard** deletes it at once.

## Share secrets

1. On **Raw secrets**, select the secrets and click **Share by link** next to
   **Delete selected**.
2. Optionally add a note and choose how long the link stays open.
3. Keep **Add a code to send separately** ticked, then click **Create link**.
4. The link and the code are shown once and are not stored anywhere. Copy the
   link, then the code, and send them over two different channels, for
   example the link in chat and the code by text. **Copy both & done** puts
   them in one message when one channel is acceptable.

A share carries the saved values; an unsaved edit is not included. Raw
secrets shows the share as waiting, then as **Opened**. A recipient who finds
the link already used, without having opened it, means someone else opened
it first: rotate those secrets.

## Receiving a Drop link

- **Asked for secrets:** fill in the rows or paste what is at hand, then
  **Encrypt and send**. Plain values are safe to paste; they are encrypted
  before they leave the browser.
- **Sent secrets:** enter the code, click **Show secrets**, then copy the
  values or download them as a `.env`. They are shown only once; refreshing
  or closing the page clears them.

An unexpected Drop link deserves a check with the person named on the page
before anything is sent or opened.
