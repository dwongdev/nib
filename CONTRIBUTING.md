# Contributing to NIB

Thanks for your interest in contributing to Network in a Box.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/matijazezelj/nib.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Test: `make validate && make install && make health`
6. Commit and push
7. Open a pull request

## Development Setup

```bash
cp .env.example .env
make install
make status
make test-alert
```

## Project Structure

```
nib/
├── suricata/    - Suricata IDS config and rules
├── crowdsec/    - CrowdSec engine and bouncer config
├── storage/     - VictoriaLogs + Vector pipeline
├── grafana/     - Dashboards and provisioning
├── docs/        - Documentation
├── scripts/     - Helper scripts
└── examples/    - Example configurations
```

## Types of Contributions

### Suricata Rules
- Add custom detection rules to `suricata/rules/custom.rules`
- Follow Suricata rule syntax and include `sid`, `rev`, `classtype`, and `msg`
- Use SID range 9000000-9999999 for custom rules

### Grafana Dashboards
- Export as JSON from Grafana UI
- Place in `grafana/dashboards/`
- Use `nib-` prefix for dashboard UIDs
- Use VictoriaLogs datasource

### CrowdSec Scenarios
- Custom scenarios go in `crowdsec/config/`
- Follow CrowdSec scenario format

### Documentation
- Keep READMEs in each component directory
- Update root README for new features

## Code Style

- **YAML**: 2-space indentation
- **JSON**: 2-space indentation, trailing newline
- **Shell/Makefile**: Quote variables, include help comments (`## description`)
- **Suricata rules**: One rule per line, include classtype and SID

## Testing

```bash
make validate          # Check config files exist
make test-rules        # Validate Suricata rule syntax
make test-alert        # Trigger test IDS alert
make health            # Verify all services running
```

## Pull Request Process

1. Update documentation for any new features
2. Add entries to relevant README files
3. Test with `make install` from a clean state
4. Describe what changed and why in the PR description

## Reporting Bugs

Include:
- NIB version / commit hash
- OS and Docker version
- Output of `make status`
- Relevant logs (`make logs-suricata`, `make logs-crowdsec`, etc.)
- Steps to reproduce

## License

Contributions are licensed under [Apache 2.0](LICENSE).
