# infrastructure/

Terraform code that defines every AWS resource. Built in Milestone 3. Nothing here is deployed until its cost and permissions have been reviewed.

```
bootstrap/          Applied once by hand: Terraform state bucket and GitHub OIDC role
environments/dev/   Calls the modules with dev settings
modules/<name>/aws/ One folder per capability (identity, web, api, storage, data, ai, security, logging, monitoring)
```

Modules are named by what they do, not by AWS service, so another cloud's version could sit beside each one later.

**Rules**

- No credentials or `.tfvars` files with real values are committed (see `.gitignore`).
- State lives in an encrypted, versioned S3 bucket, never in Git.
- Every change goes through a pull request with an automated security scan (Checkov) before it can be applied.
