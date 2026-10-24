# Purpose

## The problem
Identity programs rarely fail on cryptography. They fail at the seams between systems: HR records a
departure, the directory account is switched off, and an app that keeps its own logins never hears about
it. Or someone changes teams, gets new rights, and keeps the old ones. Each gap is small; together they
are how former staff, contractors and stolen sessions keep access.

## What this repo does
It builds the whole employee identity lifecycle as small, testable Python modules for Zestlane, a
made-up food-delivery company, and proves each control with a test. The headline experiment runs the
same story twice, once with a shallow offboarding and once with the full process, and prints the
difference.

## Who it is for
* **Recruiters and hiring managers:** a compact view of IAM engineering judgement (lifecycle, revocation,
  governance) with measured results.
* **Engineers adopting the ideas:** the [implementation guide](implementation-guide.md) maps every module
  to the control you would configure or build in a real identity stack.
* **Me (learning):** a place to make each IAM term concrete and testable instead of a list of acronyms.

## Scope
Workforce IAM is the focus. Customer identity, partner guests and machine identities are modelled only
briefly; [Jagadish-agent-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-agent-identity-security)
and [Jagadish-machine-identity-security](https://github.com/jagadishmazure-jpg/Jagadish-machine-identity-security)
cover non-human identity in depth.
