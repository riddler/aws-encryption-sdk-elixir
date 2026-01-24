---
description: Create GitHub issues with intelligent analysis and labeling
model: sonnet
---

# Create Issue

Create a new GitHub issue with proper structure, labels, and context.

## Process

### Step 1: Gather Information

If arguments were provided, analyze them. Otherwise, ask the user for:
- A brief title or description of the issue
- Any additional context, requirements, or details
- (Optional) Related files, components, or areas of the codebase

### Step 2: Analyze and Structure

1. **Analyze user input** to extract:
   - Main problem or feature request
   - Technical components involved
   - Priority indicators (urgent, blocking, nice-to-have, etc.)
   - Affected areas of codebase

2. **Determine appropriate labels**:
   - One **category label** (required)
   - Zero or more **area labels** (based on components affected)

### Label Reference

#### Category Labels (choose one)

| Label | When to Use |
|-------|-------------|
| `feature` | New functionality |
| `bug` | Something broken |
| `improvement` | Enhancement to existing functionality |
| `refactor` | Cleanup, refactoring, performance |
| `documentation` | Docs, comments, guides |
| `research` | Investigation, spikes |

#### Area Labels (choose zero or more)

| Label | When to Apply |
|-------|---------------|
| `keyring` | Keyring implementations (Raw AES, Raw RSA, KMS, Multi) |
| `cmm` | Cryptographic materials manager |
| `crypto` | Cryptographic operations (AES-GCM, HKDF, ECDSA) |
| `format` | Message format serialization (header, body, footer) |
| `client-api` | Public encrypt/decrypt API |
| `testing` | Test infrastructure, test vectors |
| `aws-integration` | AWS KMS integration |

### Step 3: Structure the Issue

**Title**: Clear and concise (50-80 characters), start with action verb when appropriate

**Body format for features/enhancements**:
```markdown
## Description
[Clear explanation of the feature]

## Context
[Why this is needed, background information]

## Proposed Solution
[High-level approach or ideas]

## Spec References
- [Link to relevant spec section if applicable]

## Acceptance Criteria
- [ ] [Specific, measurable outcome]
- [ ] [Another criterion]
- [ ] Passes relevant test vectors

## Technical Notes
- Affected files/components: [list]
- Dependencies: [any related issues or requirements]
- Considerations: [edge cases, constraints, etc.]
```

**Body format for bugs**:
```markdown
## Bug Description
[What's wrong and how it manifests]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [See error]

## Expected Behavior
[What should happen]

## Actual Behavior
[What actually happens]

## Technical Context
- Affected files: [list]
- Error messages: [if any]
- Related issues: [if any]

## Possible Solution
[If you have ideas on how to fix it]
```

### Step 4: Present Draft for Approval

Before creating, show the user:

```
I've prepared the following issue:

**Title**: Implement Raw AES keyring

**Labels**: `feature`, `keyring`, `crypto`

**Body**:
## Description
Implement the Raw AES keyring per the AWS Encryption SDK specification.

## Context
The Raw AES keyring is needed for local encryption scenarios where
keys are managed outside of AWS KMS.

## Spec References
- [Raw AES Keyring Spec](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md)

## Acceptance Criteria
- [ ] Implements `on_encrypt` callback
- [ ] Implements `on_decrypt` callback
- [ ] Uses AES-GCM for wrapping
- [ ] Passes Raw AES keyring test vectors

## Technical Notes
- Affected files: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
- Dependencies: Keyring behaviour (#XX)
- Uses `:crypto.crypto_one_time_aead/6`

---

Options:
1. Create as-is
2. Adjust title
3. Add/remove labels
4. Edit body
```

### Step 5: Create the Issue

After user approval:

```bash
gh issue create \
  --title "Issue title here" \
  --body "$(cat <<'EOF'
Issue body here
EOF
)" \
  --label "feature" \
  --label "keyring" \
  --label "crypto"
```

### Step 6: Confirm and Suggest Next Steps

After creation:

```
Created issue #42: "Implement Raw AES keyring"
https://github.com/owner/repo/issues/42

**Next steps**:
- `/research_issue #42` - Research the codebase and specs for this issue
- `/create_plan #42` - Create an implementation plan
```

## Important Guidelines

- Always present draft for approval before creating
- Include spec references when implementing SDK features
- Suggest related test vectors in acceptance criteria
- Keep titles action-oriented and concise
- Be thorough but not verbose in the body
