# Security Policy

Cornela is a defensive audit and monitoring tool. It must not include exploit code or instructions for exploiting production systems.

## Supported Versions

Cornela is currently experimental. Security fixes are expected to target the latest published release.

## Reporting Security Issues

Please report security issues privately through GitHub Security Advisories for `chud-lori/cornela` when available.

Do not open a public issue with exploit details, crash reproducers that weaponize a vulnerability, secrets, or host-specific sensitive data.

## Scope

In scope:

- bugs that could cause unsafe behavior when running Cornela
- incorrect packaging or release integrity issues
- privilege-handling issues in install or monitor flows
- parsing bugs that expose sensitive local data unexpectedly

Out of scope:

- requests for exploit code
- unsupported kernel behavior unrelated to Cornela
- findings that only confirm Cornela reports a defensive risk signal

## Safe Use

Run Cornela only on systems you own or are authorized to assess. Cornela does not prove exploitability and does not replace patching, seccomp, AppArmor, SELinux, microVMs, or dedicated hosts.
