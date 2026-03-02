# frostr-utils Security Notes

- Treat share material as highly sensitive secret data.
- Treat onboarding packages as sensitive because they include a secret share.
- Limit relay list to trusted bootstrap relays.
- Enforce strict prefix and bounds checks when decoding (`onboard` package payloads, relay count/length, no trailing bytes).
