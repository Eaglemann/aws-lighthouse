# Security policy and threat model

## Supported versions

AWS Lighthouse is currently alpha. Security fixes are applied to the latest
`main` branch and most recent release only.

## Reporting a vulnerability

Use GitHub's private security-advisory flow for
`Eaglemann/aws-lighthouse`. Do not open a public issue containing credentials,
account IDs, exploitable payloads, or unredacted logs. Include the affected
version/commit, impact, minimal reproduction, and suggested mitigation if known.

## Trust boundaries

- AWS credentials remain in the boto3 provider chain; Lighthouse does not store
  access keys in its database.
- AWS API responses, Terraform files, model output, and webhook endpoints are
  untrusted inputs.
- The Ollama model is not a security principal. Tool authorization is enforced
  by code after model output.
- SQLite and logs may contain account/resource identifiers and finding details;
  protect the user's home directory and backups.

## Controls

- Exact, fail-closed agent tool allowlist. Unknown tools require approval.
- Arbitrary file/Terraform reads and all local/AWS mutations require approval.
- Generic shell execution is not exposed to the model.
- Sensitive path checks block common credential stores even after approval.
- Interactive remediations require per-resource confirmation and explicit
  region validation where required.
- Scanner errors use typed envelopes; degraded scopes cannot auto-resolve
  opportunities or baseline findings.
- Regional identity includes region, preventing cross-region resource-ID mixups.
- Adaptive AWS retries and paginators reduce false absence from throttling and
  truncated responses.
- Dependency audit has no vulnerability exceptions. GitHub Actions are pinned
  by SHA. Gitleaks downloads are checksum-verified.
- `.gitignore` covers dotenv variants, private keys, Terraform state/variables,
  local AWS/MCP config, and local databases.

## Limitations

- Read-only AWS APIs can still expose sensitive metadata and incur API charges.
- Least-privilege IAM varies with enabled scanners. A missing permission creates
  degraded evidence; it should not be silently broadened.
- Approval protects against unconsented execution, not a user approving a bad
  plan. Verify resource, account, region, reversibility, and backup state.
- Webhook URLs may embed credentials. Configure them through environment
  variables and use an allowlisted HTTPS endpoint.
- Ollama traffic is sent to `OLLAMA_HOST`; using a remote host sends prompts and
  tool results outside the machine.
- Local file path blocklists cannot enumerate every sensitive file. The primary
  control is explicit approval and a dedicated low-privilege runtime user.

## Recommended AWS deployment

1. Create a dedicated sandbox account or read-only role.
2. Enable only required scans in the policy file.
3. Run the strict live qualification with the expected account ID.
4. Review degraded permissions rather than attaching broad administrator access.
5. Enable interactive mutation only for a separate role and session with a short
   lifetime, MFA, CloudTrail, and change-control context.
