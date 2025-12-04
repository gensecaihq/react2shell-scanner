---
name: Rule Update Request
about: Request an update to CVE rules or add a new CVE
title: '[RULE] '
labels: rules
assignees: ''
---

## Rule Update Type
- [ ] New CVE rule
- [ ] Update vulnerable version range
- [ ] Add newly fixed version
- [ ] Correct existing rule

## CVE Information

**CVE ID**: CVE-YYYY-XXXXX

**Affected Package(s)**:
- Package name:
- Vulnerable versions:
- Fixed versions:

**Severity**: Critical / High / Medium / Low

**CVSS Score**: (if known)

## Sources
Please provide official sources:
- [ ] Official advisory URL:
- [ ] GitHub Security Advisory:
- [ ] CVE database entry:
- [ ] Vendor announcement:

## Current Behavior
How the scanner currently handles this (if applicable).

## Expected Behavior
What the scanner should detect after this update.

## Proposed Rule Change
If you've drafted a rule update, paste the JSON here:
```json
{
  "packages": [
    {
      "name": "package-name",
      "vulnerable": "version-range",
      "fixed": ["fixed-version"]
    }
  ]
}
```

## Additional Context
Any other relevant information about this CVE or rule update.
