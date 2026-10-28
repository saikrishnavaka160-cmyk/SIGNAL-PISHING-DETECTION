# Signal — local-first phishing email screening

Signal is a static website built around the supplied Python phishing detector. It screens pasted email text or a local email file, explains the rule score, and summarizes labeled CSV datasets.

## Run it

Open index.html in a modern browser. It runs as a static page with no installation step.

## Privacy

Email text and CSV contents are analyzed in browser memory and remain on your device. Results show aggregate counts rather than email bodies. Clear or close the page to discard the current content.

## Features

- Rule-based analysis for urgency, credential and payment language, authentication failures, deceptive link labels, URL shorteners, raw IP links, unusual domain encoding, HTTP links, brand and sender mismatches, and executable attachments.
- Email file selection and drag-and-drop, plus a sample message.
- CSV dataset analysis with common text and label column auto-detection, risk counts, common indicators, a configurable positive score threshold, and confusion-matrix metrics.
- A scoring guide that explains the rules and the limits of a low-risk result.

## Limitations

This is an early-stage local screening prototype. Browser-side email parsing handles common plain text, HTML, quoted-printable, and base64 MIME parts; complex messages may be read imperfectly. Authentication results may be missing or untrusted in forwarded messages. The rules do not inspect remote websites, so interpret results alongside normal security controls.
