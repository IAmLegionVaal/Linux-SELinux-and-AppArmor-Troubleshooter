# Linux SELinux and AppArmor Troubleshooter

A read-only Bash toolkit for collecting mandatory-access-control status, denials, profiles, contexts, audit evidence, and affected-service information on SELinux- and AppArmor-based systems.

## Purpose

This project helps support and security engineers investigate access denials without weakening enforcement or changing policy.

## Checks performed

- Detects whether SELinux, AppArmor, both, or neither are present
- SELinux mode, policy type, status, booleans, file contexts, and loaded-policy information
- Recent AVC and USER_AVC denials from `ausearch` or journal logs
- Optional `audit2why` interpretation when available
- AppArmor loaded, enforcing, complain, and unconfined profiles
- Recent AppArmor denial events
- Security service and audit daemon state
- Process security labels and selected filesystem contexts
- Text, CSV, and JSON reports

## Usage

```bash
chmod +x src/mac_policy_troubleshooter.sh
sudo ./src/mac_policy_troubleshooter.sh
```

Investigate a particular service or path:

```bash
sudo ./src/mac_policy_troubleshooter.sh --service nginx --path /var/www/html --hours 48
```

## Safety

The toolkit does not disable enforcement, set permissive mode, unload profiles, change booleans, relabel files, generate modules, install policy, or modify audit configuration.

## Interpretation

A denial is evidence of a blocked action, not automatic proof that policy is incorrect. Validate the expected application behaviour, path ownership, service account, network context, and approved security design before remediation.

## Requirements

- Bash 4+
- Root privileges for complete audit evidence
- Optional SELinux tools: `sestatus`, `ausearch`, `semanage`, `matchpathcon`, `audit2why`
- Optional AppArmor tools: `aa-status`, `apparmor_status`

## Validation ideas

- Enforcing SELinux host with no denials
- Lab AVC denial
- AppArmor enforcing profile
- AppArmor complain-mode profile
- Host with auditd stopped
- Host without either framework

## Author

Dewald Pretorius — L2 IT Support Engineer
