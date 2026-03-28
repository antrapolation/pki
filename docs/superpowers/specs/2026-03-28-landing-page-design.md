# PQC CA System — Marketing Landing Page

## Overview

Single-file marketing landing page (`index.html`) for the Post-Quantum Certificate Authority system by Antrapolation Technology Sdn Bhd. Targets government agencies and enterprise IT decision-makers in Malaysia and the region.

## Requirements

- Single `index.html` with inline CSS and JS — no build step, no external dependencies
- Dark theme matching antrapol.com brand aesthetic
- Bilingual: English (primary) + Bahasa Malaysia with toggle
- Responsive (mobile-first)
- CTA: "Request a Demo" via mailto:info@antrapol.com
- No backend, no form submission service

## Page Structure

### 1. Navigation Bar
- Company name / logo text: "Antrapolation Technology"
- Language toggle: EN | BM
- Sticky on scroll

### 2. Hero Section
- **EN Headline:** "Post-Quantum Certificate Authority"
- **EN Subline:** "Future-proof your PKI infrastructure with Malaysia's first PQC-ready CA system"
- **BM Headline:** "Pihak Berkuasa Sijil Pasca-Kuantum"
- **BM Subline:** "Lindungi infrastruktur PKI anda dengan sistem CA sedia PQC pertama di Malaysia"
- CTA button: "Request a Demo" / "Mohon Demo"

### 3. Features Grid (6 cards)

| Feature | EN Title | BM Title |
|---------|----------|----------|
| PQC | Post-Quantum Ready | Sedia Pasca-Kuantum |
| Multi-tenant | Multi-Tenant Architecture | Seni Bina Berbilang Penyewa |
| Credentials | Cryptographic Credentials | Kelayakan Kriptografi |
| Ceremony | Key Ceremony Manager | Pengurus Upacara Kunci |
| HSM | HSM Integration | Integrasi HSM |
| Validation | OCSP/CRL Validation | Pengesahan OCSP/CRL |

Each card has: icon (CSS/emoji), title, 2-sentence description.

### 4. How It Works (4 steps)
1. Platform Setup — Create tenant with isolated database
2. CA Bootstrap — Initialize admin with dual keypairs + key ceremony
3. RA Configuration — Set up certificate profiles and validation policies
4. Certificate Issuance — Submit CSR, validate, sign, distribute

### 5. Contact Section
- Headline: "Ready to secure your infrastructure?" / "Bersedia untuk melindungi infrastruktur anda?"
- Brief paragraph about requesting a personalized demo
- mailto:info@antrapol.com button

### 6. Footer
- Antrapolation Technology Sdn Bhd
- Link to antrapol.com
- Copyright 2026

## Technical Design

### i18n
- JS object with `en` and `bm` keys containing all translatable strings
- Elements use `data-i18n="key"` attributes
- Toggle button swaps `textContent` of all `[data-i18n]` elements
- Preference saved to `localStorage`

### Styling
- Dark background (~#0a0a0f deep navy/black)
- Teal/cyan accent for CTAs and highlights
- CSS Grid for features layout
- CSS scroll-based fade-in animations (IntersectionObserver)
- No external fonts — system font stack for fast load
- Fully responsive breakpoints (mobile, tablet, desktop)

### Deployment
- Drop `index.html` anywhere — Caddy, S3, Netlify, GitHub Pages
- Zero dependencies, zero build step
- File location in repo: `landing/index.html`
