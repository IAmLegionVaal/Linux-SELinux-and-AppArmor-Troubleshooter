# Linux SELinux and AppArmor Troubleshooter

A Linux support toolkit for diagnosing mandatory-access-control problems and applying selected guarded SELinux or AppArmor repairs.

## Diagnostic script

```bash
chmod +x src/mac_policy_troubleshooter.sh
sudo ./src/mac_policy_troubleshooter.sh
```

Investigate one service or path:

```bash
sudo ./src/mac_policy_troubleshooter.sh --service nginx --path /var/www/html --hours 48
```

## Repair script

Preview a repair:

```bash
chmod +x src/mac_policy_repair.sh
sudo ./src/mac_policy_repair.sh --restorecon /var/www/html --dry-run
```

Restore default SELinux labels below a selected path:

```bash
sudo ./src/mac_policy_repair.sh --restorecon /var/www/html
```

Place one AppArmor profile in enforce mode:

```bash
sudo ./src/mac_policy_repair.sh --apparmor-enforce usr.sbin.nginx
```

Validate and reload one AppArmor profile file:

```bash
sudo ./src/mac_policy_repair.sh --reload-apparmor /etc/apparmor.d/usr.sbin.nginx
```

Restart the installed audit or AppArmor service:

```bash
sudo ./src/mac_policy_repair.sh --restart-audit
```

## What the repair does

- Restores default SELinux labels below one selected path.
- Places one selected AppArmor profile in enforce mode.
- Validates and reloads one selected AppArmor profile file.
- Restarts the installed audit or AppArmor service.
- Captures enforcement state and recent denial evidence before and after repair.
- Supports confirmation prompts, dry-run, logs and clear exit codes.

## Safety and limitations

The repair does not disable SELinux or AppArmor, switch profiles into complain mode, generate policy modules or alter policy booleans. Denials caused by incorrect application behaviour or unsupported policy still require technician and security review.

## Author

Dewald Pretorius — L2 IT Support Engineer
