# Security and Data Handling

## Production access logs

The production Nginx access log used in the paper contains real website traffic and is not included in this repository. Raw web logs can contain IP addresses, search terms, identifiers, referrers, user-agent strings, and other information that may be sensitive or identifying.

## Request bodies

The SQLi detector intentionally uses query parameters present in standard web-server access logs. Standard Apache/Nginx access logging does not include HTTP request bodies by default. Although body logging can be enabled with additional instrumentation, indiscriminate capture may expose passwords, tokens, personal information, and other sensitive application data.

## Model artefacts

The `.joblib` model files are Python pickle-based artefacts. Only load them from a trusted repository/source.

## Secrets

Do not commit `.env` files containing environment-specific credentials or endpoints. This repository ships only `.env.example`.
