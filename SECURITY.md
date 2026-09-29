# Security Policy

hive-immune is security software, so vulnerabilities in it can weaken the
networks it is meant to protect. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Instead, use GitHub's private vulnerability
reporting: go to the repository's **Security** tab and choose
**Report a vulnerability**.

Please include:

- affected package or component and version / commit
- a description of the issue and its impact
- steps or a minimal proof of concept to reproduce it

## What to expect

| Step | Target |
|---|---|
| Acknowledge report | within 3 business days |
| Initial assessment and severity | within 7 days |
| Fix for critical, reachable issues | as fast as possible, aiming for 30 days |

We will coordinate disclosure with you and credit you in the advisory unless
you prefer to remain anonymous.

## Scope

Of particular interest are issues that let an attacker:

- forge, replay or tamper with signals accepted by the field
- force containment or isolation of healthy nodes
- suppress detection of a real intrusion
- exhaust memory or CPU of an agent

## Supported versions

The project is pre-1.0. Only the latest commit on `main` receives fixes.
