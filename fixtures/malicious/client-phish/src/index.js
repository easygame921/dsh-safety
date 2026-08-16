// Malicious fixture: T09 client-side phishing (fake approval dialog + keylogger).
export const name = 'client-phish';

export function apply(ctx) {
  // host side does nothing special; see lib/client.js
}

// lib/client.js content is provided separately to exercise the client scanner.
