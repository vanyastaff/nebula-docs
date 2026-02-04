---
title: "{{EXAMPLE_TITLE}}"
tags: [example, {{CREDENTIAL_TYPE}}, {{USE_CASE}}]
status: draft
lang: ru
created: {{DATE}}
last_updated: {{DATE}}
audience: [beginner, intermediate]
estimated_reading: 10
---

# {{EXAMPLE_TITLE}}

> **TL;DR**: {{ONE_SENTENCE_DESCRIPTION}}

## Use Case

{{USE_CASE_DESCRIPTION}}

**Когда использовать**:
- {{SCENARIO_1}}
- {{SCENARIO_2}}
- {{SCENARIO_3}}

## Предварительные требования

- nebula-credential v{{VERSION}}+
- Понимание: [[{{PREREQUISITE_CONCEPT}}]]
- {{ADDITIONAL_PREREQ}}

## Полный пример кода

\`\`\`rust
// File: examples/{{EXAMPLE_NAME}}.rs
// Description: {{EXAMPLE_DESCRIPTION}}
// 
// To run:
//   cargo run --example {{EXAMPLE_NAME}}

{{COMPLETE_CODE_WITH_COMMENTS}}
\`\`\`

## Зависимости

Добавьте в `Cargo.toml`:

\`\`\`toml
[dependencies]
nebula-credential = "{{VERSION}}"
{{ADDITIONAL_DEPENDENCIES}}

[dev-dependencies]
{{DEV_DEPENDENCIES}}
\`\`\`

## Объяснение ключевых частей

### Часть 1: {{KEY_PART_1_TITLE}}

\`\`\`rust
{{KEY_PART_1_CODE}}
\`\`\`

{{EXPLANATION_1}}

### Часть 2: {{KEY_PART_2_TITLE}}

\`\`\`rust
{{KEY_PART_2_CODE}}
\`\`\`

{{EXPLANATION_2}}

### Часть 3: {{KEY_PART_3_TITLE}}

\`\`\`rust
{{KEY_PART_3_CODE}}
\`\`\`

{{EXPLANATION_3}}

## Ожидаемый результат

При запуске примера вы должны увидеть:

\`\`\`
{{EXPECTED_OUTPUT}}
\`\`\`

## Варианты

### Вариант 1: {{VARIATION_1_TITLE}}

{{VARIATION_1_DESCRIPTION}}

\`\`\`rust
{{VARIATION_1_CODE}}
\`\`\`

### Вариант 2: {{VARIATION_2_TITLE}}

{{VARIATION_2_DESCRIPTION}}

\`\`\`rust
{{VARIATION_2_CODE}}
\`\`\`

## Важные замечания

> [!warning] Предупреждение
> {{SECURITY_WARNING_IF_APPLICABLE}}

> [!tip] Лучшая практика
> {{BEST_PRACTICE_TIP}}

## Связанные примеры

- {{RELATED_EXAMPLE_1}}: [[{{EXAMPLE_1}}]]
- {{RELATED_EXAMPLE_2}}: [[{{EXAMPLE_2}}]]
- {{RELATED_EXAMPLE_3}}: [[{{EXAMPLE_3}}]]

## See Also

- Концепция: [[{{RELATED_CONCEPT}}]]
- How-To: [[{{RELATED_HOWTO}}]]
- Troubleshooting: [[{{TROUBLESHOOTING}}]]

---

**Validation Checklist**:
- [ ] Code is complete and runnable
- [ ] Cargo.toml dependencies listed
- [ ] Key parts explained with comments
- [ ] Expected output shown
- [ ] At least one variation provided
- [ ] Example tested successfully
