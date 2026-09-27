# Sentinel — Security Header Analyzer

A lightweight Python tool for analyzing HTTP security headers and identifying common web security hardening gaps.

> Learn. Analyze. Understand. Secure.

---

## 01 / OVERVIEW

**Sentinel** is a lightweight security-focused Python tool designed to inspect HTTP response headers and highlight missing or weak security configurations.

The project is built as a learning-focused security utility while exploring how web applications communicate and how security controls can be implemented at the HTTP layer.

---

## 02 / FEATURES

- HTTP security header analysis
- Detection of missing security headers
- Basic security hardening recommendations
- Simple command-line workflow
- Lightweight Python implementation
- Beginner-friendly security research project

---

## 03 / SECURITY HEADERS

Sentinel currently focuses on commonly recommended HTTP security headers such as:

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Helps reduce content injection attacks |
| `Strict-Transport-Security` | Enforces HTTPS connections |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing |
| `X-Frame-Options` | Helps protect against clickjacking |
| `Referrer-Policy` | Controls referrer information |
| `Permissions-Policy` | Restricts browser capabilities |

---

## 04 / TECH STACK

**Language**

`Python`

**Libraries**

`Requests`

**Environment**

`Linux` · `Windows` · `Terminal`

---

## 05 / INSTALLATION

Clone the repository:

```bash
git clone https://github.com/hassanshajjat/sentinel-security-header-analyzer.git
