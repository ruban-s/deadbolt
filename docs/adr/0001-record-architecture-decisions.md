# 1. Record architecture decisions

Date: 2026-07-08

## Status

Accepted

## Context

`deadbolt` makes security-critical design choices (hashing, session model, cookie handling, the
framework-agnostic contract). These need a durable, reviewable record so defaults are never weakened
silently and future contributors understand the "why".

## Decision

We keep Architecture Decision Records in `docs/adr/`, one file per decision, numbered sequentially,
using the Nygard format (Context / Decision / Consequences). Any change to a security default requires
a new ADR. The CODEOWNERS file routes ADR review to the maintainer.

## Consequences

A small process cost per significant decision, in exchange for a defensible history of security
choices and a clear onboarding trail.
