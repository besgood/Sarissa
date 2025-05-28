# Contributing to Sarissa

Thank you for your interest in contributing to Sarissa! This document provides guidelines and instructions for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.76 or later
- PostgreSQL 12 or later
- Git
- Docker (optional)

### Local Development Environment

1. Clone the repository:
```bash
git clone https://github.com/besgood/Sarissa.git
cd Sarissa
```

2. Install dependencies:
```bash
cargo build
```

3. Set up the database:
```bash
psql -U postgres -c "CREATE DATABASE sarissa_dev;"
psql -U postgres -c "CREATE USER sarissa_dev WITH PASSWORD 'dev_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE sarissa_dev TO sarissa_dev;"
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your local settings
```

5. Run migrations:
```bash
cargo run --bin sarissa-migrate
```

## Development Workflow

### Branching Strategy

- `main`: Production-ready code
- `develop`: Development branch
- `feature/*`: New features
- `bugfix/*`: Bug fixes
- `release/*`: Release preparation

### Commit Guidelines

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

### Pull Request Process

1. Create a new branch from `develop`
2. Make your changes
3. Write/update tests
4. Update documentation
5. Submit a pull request

Pull request template:
```markdown
## Description
[Describe your changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Documentation
- [ ] README updated
- [ ] API documentation updated
- [ ] Code comments added/updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No new warnings
```

## Code Style

### Rust Style Guide

Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/style/naming/README.html):

- Use `snake_case` for variables and functions
- Use `CamelCase` for types and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Maximum line length: 100 characters
- Use 4 spaces for indentation

### Documentation

- Document all public APIs
- Include examples in documentation
- Keep README up to date
- Document configuration options

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

```bash
cargo test --test '*'
```

### End-to-End Tests

```bash
cargo test --test e2e
```

## Security

### Security Policy

- Report security vulnerabilities to security@sarissa.dev
- Do not disclose security issues publicly
- Follow responsible disclosure guidelines

### Code Security

- No hardcoded credentials
- Use environment variables for secrets
- Follow OWASP security guidelines
- Regular security audits

## Release Process

1. Update version numbers
2. Update changelog
3. Create release branch
4. Run full test suite
5. Create release tag
6. Deploy to staging
7. Deploy to production

## Support

- GitHub Issues for bug reports
- GitHub Discussions for questions
- Documentation for usage help
- Security email for vulnerabilities

## License

By contributing to Sarissa, you agree that your contributions will be licensed under the project's license. 