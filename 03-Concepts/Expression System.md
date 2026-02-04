---
title: Expression System
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Expression System

**The Expression System enables dynamic data access and transformation within workflows without writing Rust code.** Expressions provide a safe, sandboxed language for referencing workflow data, transforming values, and making runtime decisions.

## Definition

In Nebula, expressions are:

- **String-based templates** — Written in workflow definitions, not Rust code
- **Type-safe** — Validated at workflow build time
- **Sandboxed** — Cannot execute arbitrary code or access system resources
- **Evaluated at runtime** — Resolved when workflow executes
- **Composable** — Can be nested and combined

Expressions are **not** a full programming language. They're a **domain-specific language (DSL)** optimized for data access and transformation in workflows.

## Why Expressions Matter

### The Problem with Hard-Coded Data Flow

Without expressions, every data transformation requires a custom action:

❌ **Too many actions** — Simple data mapping needs full action implementation
❌ **Boilerplate code** — Repetitive transformation logic
❌ **Hard to modify** — Changing data flow requires code changes
❌ **Not declarative** — Logic hidden in action implementations
❌ **Workflow complexity** — Extra nodes for simple transformations

**Real-world consequences**:
- Need to extract `user.email` from previous node → write ExtractEmailAction
- Need to format a string → write FormatStringAction
- Need to access workflow parameter → write GetParameterAction
- Workflow becomes cluttered with trivial actions

### The Nebula Approach

Expressions solve these problems:

✅ **Inline transformations** — Simple logic in workflow definition
✅ **Declarative** — Data flow visible in workflow structure
✅ **Type-safe** — Compilation checks expression validity
✅ **No boilerplate** — Common operations built-in
✅ **Clean workflows** — Focused on business logic, not plumbing

## Core Principles

### 1. Declarative Data Access

Access data from workflow context using dot notation:

```rust
// Workflow parameters
${workflow.params.user_id}
${workflow.params.options.retry_count}

// Previous node output
${node.fetch_user.output.email}
${node.validate_payment.output.status}

// Workflow memory
${memory.session_id}
${memory.user_preferences.theme}

// Current timestamp
${workflow.execution.started_at}
${workflow.execution.id}
```

**Why?** Makes data dependencies explicit and visible.

### 2. Type Safety

Expressions are type-checked at workflow build time:

```rust
let workflow = WorkflowBuilder::new("my_workflow")
    .add_node("fetch_user", FetchUserAction)
    .add_node("send_email", SendEmailAction)
    .add_edge("fetch_user", "send_email", |output| {
        // This expression is validated at build time
        expr!({
            "to": "${node.fetch_user.output.email}",
            "subject": "Welcome ${node.fetch_user.output.name}!"
        })
    })
    .build()?;  // Fails if expression invalid
```

**Why?** Catch errors early, before deployment.

### 3. Sandboxed Execution

Expressions cannot:
- Execute system commands
- Read/write files
- Make network requests
- Access environment variables
- Run arbitrary code

```rust
// ❌ NOT ALLOWED - security violation
${system("rm -rf /")}
${env.AWS_SECRET_KEY}
${file.read("/etc/passwd")}

// ✅ ALLOWED - safe operations
${user.email}
${string.uppercase(user.name)}
${workflow.params.user_id + 100}
```

**Why?** Security. Workflows can be user-defined; expressions must be safe.

### 4. Performance

Expressions are:
- **Parsed once** — At workflow build time
- **Compiled to bytecode** — Fast evaluation
- **Cached** — Results memoized when possible

```rust
// Expensive operation: parsed and compiled once
let expr = Expression::parse("${string.uppercase(node.fetch.output.name)}")?;

// Fast operation: evaluate compiled expression
let result = expr.evaluate(&context)?;  // Microseconds
```

**Why?** Workflows execute frequently. Expressions must be fast.

## Expression Syntax

### Basic Syntax

Expressions use `${...}` syntax:

```rust
// Simple variable access
"${workflow.params.user_id}"

// Nested property access
"${node.fetch_user.output.contact.email}"

// Function calls
"${string.uppercase(node.fetch_user.output.name)}"

// Arithmetic
"${workflow.params.price * 1.08}"  // Add 8% tax

// String interpolation
"Hello ${user.name}, your order #${order.id} is ready!"
```

### Operators

**Arithmetic**:
```rust
${a + b}      // Addition
${a - b}      // Subtraction
${a * b}      // Multiplication
${a / b}      // Division
${a % b}      // Modulo
${a ^ b}      // Exponentiation
```

**Comparison**:
```rust
${a == b}     // Equality
${a != b}     // Inequality
${a > b}      // Greater than
${a >= b}     // Greater than or equal
${a < b}      // Less than
${a <= b}     // Less than or equal
```

**Logical**:
```rust
${a && b}     // AND
${a || b}     // OR
${!a}         // NOT
```

**Null coalescing**:
```rust
${a ?? b}     // If a is null, use b
${user.middle_name ?? ""}  // Default to empty string
```

### Data Access Patterns

**Workflow Parameters**:
```rust
${workflow.params.user_id}
${workflow.params.options.retry_count}
${workflow.params.data[0].id}
```

**Node Outputs**:
```rust
${node.fetch_user.output.email}
${node.previous_step.output.results[0]}
${node.validate.output.is_valid}
```

**Workflow Memory**:
```rust
${memory.session_id}
${memory.counters.requests}
${memory.cache.user_data}
```

**Workflow Metadata**:
```rust
${workflow.id}                    // Workflow instance ID
${workflow.execution.started_at}  // Execution start time
${workflow.execution.duration}    // How long running (if complete)
${workflow.name}                  // Workflow definition name
```

**Current Date/Time**:
```rust
${now()}                    // Current timestamp
${date.format(now(), "YYYY-MM-DD")}
${date.add_days(now(), 7)}  // One week from now
```

## Built-in Functions

### String Functions

```rust
// Convert case
${string.uppercase("hello")}      // "HELLO"
${string.lowercase("WORLD")}      // "world"
${string.titlecase("hello world")} // "Hello World"

// Trim whitespace
${string.trim("  hello  ")}       // "hello"
${string.trim_start("  hello")}   // "hello"
${string.trim_end("hello  ")}     // "hello"

// Length and substrings
${string.length("hello")}         // 5
${string.substring("hello", 0, 2)} // "he"
${string.slice("hello", 1, 4)}    // "ell"

// Search and replace
${string.contains("hello", "ell")} // true
${string.starts_with("hello", "he")} // true
${string.ends_with("hello", "lo")} // true
${string.replace("hello world", "world", "there")} // "hello there"

// Split and join
${string.split("a,b,c", ",")}     // ["a", "b", "c"]
${string.join(["a", "b", "c"], "-")} // "a-b-c"

// Format
${string.format("Hello {}", user.name)}
${string.format("User {0} has {1} items", user.id, cart.count)}
```

### Math Functions

```rust
// Rounding
${math.round(3.14159)}       // 3
${math.ceil(3.2)}            // 4
${math.floor(3.8)}           // 3
${math.round_to(3.14159, 2)} // 3.14

// Min/max
${math.min(5, 10)}           // 5
${math.max(5, 10)}           // 10
${math.clamp(15, 0, 10)}     // 10 (clamped to range)

// Absolute value and sign
${math.abs(-5)}              // 5
${math.sign(-5)}             // -1

// Trigonometry
${math.sin(angle)}
${math.cos(angle)}
${math.tan(angle)}

// Logarithms
${math.log(100, 10)}         // 2 (log base 10)
${math.ln(2.71828)}          // 1 (natural log)
${math.exp(1)}               // 2.71828
```

### Array Functions

```rust
// Length and access
${array.length([1, 2, 3])}        // 3
${array.get([1, 2, 3], 0)}        // 1
${array.first([1, 2, 3])}         // 1
${array.last([1, 2, 3])}          // 3

// Transformation
${array.map([1, 2, 3], |x| x * 2)} // [2, 4, 6]
${array.filter([1, 2, 3], |x| x > 1)} // [2, 3]
${array.reduce([1, 2, 3], 0, |acc, x| acc + x)} // 6

// Aggregation
${array.sum([1, 2, 3])}           // 6
${array.avg([1, 2, 3])}           // 2
${array.min([3, 1, 2])}           // 1
${array.max([3, 1, 2])}           // 3

// Membership
${array.contains([1, 2, 3], 2)}   // true
${array.index_of([1, 2, 3], 2)}   // 1

// Combination
${array.concat([1, 2], [3, 4])}   // [1, 2, 3, 4]
${array.slice([1, 2, 3, 4], 1, 3)} // [2, 3]
${array.reverse([1, 2, 3])}       // [3, 2, 1]
${array.sort([3, 1, 2])}          // [1, 2, 3]
```

### Object Functions

```rust
// Property access
${object.get(user, "email")}         // user.email
${object.get_nested(user, "contact.email")} // user.contact.email

// Check properties
${object.has(user, "email")}         // true if user.email exists
${object.keys(user)}                 // ["id", "name", "email"]
${object.values(user)}               // [123, "Alice", "alice@example.com"]

// Merge objects
${object.merge({a: 1}, {b: 2})}      // {a: 1, b: 2}
${object.merge_deep(obj1, obj2)}     // Deep merge
```

### Date/Time Functions

```rust
// Current time
${now()}                              // Current UTC timestamp
${date.now()}                         // Alias for now()

// Formatting
${date.format(timestamp, "YYYY-MM-DD")} // "2024-03-15"
${date.format(timestamp, "HH:mm:ss")}   // "14:30:45"
${date.format(timestamp, "ddd MMM DD")} // "Fri Mar 15"

// Parsing
${date.parse("2024-03-15", "YYYY-MM-DD")}
${date.parse_iso8601("2024-03-15T14:30:00Z")}

// Arithmetic
${date.add_seconds(timestamp, 60)}    // Add 1 minute
${date.add_minutes(timestamp, 30)}    // Add 30 minutes
${date.add_hours(timestamp, 2)}       // Add 2 hours
${date.add_days(timestamp, 7)}        // Add 1 week
${date.subtract_days(timestamp, 1)}   // Subtract 1 day

// Comparison
${date.is_after(date1, date2)}        // date1 > date2
${date.is_before(date1, date2)}       // date1 < date2
${date.diff_seconds(date1, date2)}    // Seconds between dates
${date.diff_days(date1, date2)}       // Days between dates

// Components
${date.year(timestamp)}               // 2024
${date.month(timestamp)}              // 3
${date.day(timestamp)}                // 15
${date.hour(timestamp)}               // 14
${date.minute(timestamp)}             // 30
```

### Conditional Functions

```rust
// If-then-else
${if(user.age >= 18, "adult", "minor")}
${if(order.total > 100, "free shipping", "standard")}

// Switch/case
${switch(
    status,
    "pending", "⏳ Processing",
    "approved", "✅ Approved",
    "declined", "❌ Declined",
    "Unknown status"  // default
)}

// Null handling
${coalesce(user.middle_name, "")}     // Use "" if null
${is_null(user.middle_name)}          // Check if null
${is_not_null(user.email)}            // Check if not null
```

### Type Functions

```rust
// Type checking
${type_of(value)}                     // "string", "number", "bool", etc.
${is_string(value)}
${is_number(value)}
${is_bool(value)}
${is_array(value)}
${is_object(value)}

// Type conversion
${to_string(123)}                     // "123"
${to_number("456")}                   // 456
${to_bool("true")}                    // true
${to_array(value)}                    // Wrap in array if not already
```

## Type System

### Supported Types

Expressions support these types:

```rust
// Primitives
String      // "hello"
Number      // 123, 45.67 (f64 internally)
Boolean     // true, false
Null        // null

// Collections
Array       // [1, 2, 3]
Object      // {key: "value"}

// Special
DateTime    // Timestamp with timezone
Duration    // Time span
```

### Type Coercion

Automatic type conversion in some operations:

```rust
// String concatenation
${"User " + user.id}              // "User 123" (number → string)

// Numeric operations
${string_num + 5}                 // If string_num is "10", result is 15

// Boolean context
${if(user.name, "has name", "no name")}  // Non-empty string is truthy
```

### Type Safety

Expressions are type-checked at workflow build time:

```rust
// ✅ Valid - types match
.add_edge("fetch_user", "send_email", |_| {
    expr!({
        "to": "${node.fetch_user.output.email}",  // String
        "subject": "Welcome!"                       // String
    })
})

// ❌ Invalid - type mismatch detected at build time
.add_edge("fetch_user", "calculate_age", |_| {
    expr!({
        "birth_date": "${node.fetch_user.output.email}"  // email is string, needs date
    })
})  // Build error: type mismatch
```

## Real-World Examples

### User Onboarding Workflow

```rust
let workflow = WorkflowBuilder::new("user_onboarding")
    .add_node("create_user", CreateUserAction)
    .add_node("send_welcome_email", SendEmailAction)
    .add_node("create_profile", CreateProfileAction)

    // Send welcome email with user data
    .add_edge("create_user", "send_welcome_email", |_| {
        expr!({
            "to": "${node.create_user.output.email}",
            "subject": "Welcome to ${workflow.params.company_name}!",
            "body": "Hello ${string.titlecase(node.create_user.output.first_name)},\n\n\
                     Thank you for joining ${workflow.params.company_name}.\n\
                     Your user ID is ${node.create_user.output.id}."
        })
    })

    // Create profile with computed values
    .add_edge("create_user", "create_profile", |_| {
        expr!({
            "user_id": "${node.create_user.output.id}",
            "display_name": "${node.create_user.output.first_name} ${node.create_user.output.last_name}",
            "joined_at": "${now()}",
            "tier": "${if(workflow.params.is_premium, \"premium\", \"standard\")}"
        })
    })

    .build()?;
```

### Order Processing with Calculations

```rust
let workflow = WorkflowBuilder::new("process_order")
    .add_node("validate_order", ValidateOrderAction)
    .add_node("calculate_total", CalculateTotalAction)
    .add_node("charge_payment", ChargePaymentAction)

    // Calculate order total with tax and shipping
    .add_edge("validate_order", "calculate_total", |_| {
        expr!({
            "subtotal": "${array.sum(array.map(node.validate_order.output.items, |item| item.price * item.quantity))}",
            "tax_rate": "${workflow.params.tax_rate ?? 0.08}",
            "tax": "${subtotal * tax_rate}",
            "shipping": "${if(subtotal > 100, 0, 10)}",  // Free shipping over $100
            "total": "${subtotal + tax + shipping}"
        })
    })

    // Charge payment with formatted amount
    .add_edge("calculate_total", "charge_payment", |_| {
        expr!({
            "amount": "${math.round_to(node.calculate_total.output.total, 2)}",
            "currency": "${workflow.params.currency ?? \"USD\"}",
            "description": "Order #${workflow.params.order_id} - ${array.length(node.validate_order.output.items)} items"
        })
    })

    .build()?;
```

### Conditional Workflow Routing

```rust
let workflow = WorkflowBuilder::new("approve_document")
    .add_node("check_document", CheckDocumentAction)
    .add_node("auto_approve", AutoApproveAction)
    .add_node("manual_review", ManualReviewAction)
    .add_node("notify_approved", NotifyAction)
    .add_node("notify_rejected", NotifyAction)

    // Route based on document value and type
    .add_edge_conditional(
        "check_document",
        "auto_approve",
        |output| expr!("${output.value < 1000 && output.type == \"invoice\"}"),
        |output| output
    )
    .add_edge_conditional(
        "check_document",
        "manual_review",
        |output| expr!("${output.value >= 1000 || output.type != \"invoice\"}"),
        |output| output
    )

    .build()?;
```

### Data Aggregation from Multiple Sources

```rust
let workflow = WorkflowBuilder::new("fetch_user_data")
    .add_node("fetch_profile", FetchProfileAction)
    .add_node("fetch_orders", FetchOrdersAction)
    .add_node("fetch_activity", FetchActivityAction)
    .add_node("aggregate", AggregateAction)

    // Aggregate data from all sources
    .add_edge("fetch_profile", "aggregate", |_| {
        expr!({
            "user": {
                "id": "${node.fetch_profile.output.id}",
                "name": "${node.fetch_profile.output.first_name} ${node.fetch_profile.output.last_name}",
                "email": "${node.fetch_profile.output.email}",
                "member_since": "${date.format(node.fetch_profile.output.created_at, \"YYYY-MM-DD\")}",
                "total_orders": "${array.length(node.fetch_orders.output.orders)}",
                "total_spent": "${array.sum(array.map(node.fetch_orders.output.orders, |order| order.total))}",
                "last_active": "${date.format(node.fetch_activity.output.last_seen, \"YYYY-MM-DD HH:mm\")}",
                "activity_days": "${date.diff_days(now(), node.fetch_profile.output.created_at)}"
            }
        })
    })

    .build()?;
```

## Best Practices

### Expression Design

- ✅ **Keep expressions simple** — Complex logic belongs in actions
- ✅ **Use descriptive names** — `${user.email}` not `${data.field1}`
- ✅ **Handle nulls** — Use `??` operator for defaults
- ✅ **Format consistently** — Use clear spacing and indentation
- ✅ **Test expressions** — Validate with sample data
- ❌ **Don't embed business logic** — Actions for complex rules
- ❌ **Don't chain too deeply** — Max 3-4 levels of nesting
- ❌ **Don't duplicate expressions** — Extract to workflow parameters

### Performance

- ✅ **Cache expensive computations** — Store in workflow memory
- ✅ **Use built-in functions** — Optimized implementations
- ✅ **Avoid repeated array iterations** — Compute once, reuse
- ❌ **Don't recompute constants** — Use workflow parameters
- ❌ **Don't nest heavy operations** — Split into multiple edges

### Security

- ✅ **Validate user input** — Don't trust workflow parameters
- ✅ **Sanitize strings** — Escape special characters
- ✅ **Limit expression complexity** — Prevent DoS via complex expressions
- ❌ **Don't expose secrets** — Credentials never in expressions
- ❌ **Don't trust external data** — Validate before using in expressions

### Maintainability

- ✅ **Document complex expressions** — Add comments
- ✅ **Use consistent formatting** — Follow team style guide
- ✅ **Test edge cases** — Null values, empty arrays, etc.
- ✅ **Version workflows** — Track expression changes
- ❌ **Don't use magic numbers** — Use named parameters
- ❌ **Don't duplicate expressions** — Create reusable components

## Limitations

Expressions **cannot**:

❌ **Execute arbitrary code** — No eval(), no system calls
❌ **Make network requests** — No HTTP, no database queries
❌ **Access file system** — No file reads/writes
❌ **Call external libraries** — Only built-in functions
❌ **Mutate data** — Expressions are pure (no side effects)
❌ **Loop indefinitely** — Recursion depth limited
❌ **Access credentials** — Security isolation

**When to use actions instead**:
- Complex business logic
- External API calls
- Database operations
- File I/O
- Stateful operations
- Long-running computations

## Related Concepts

- [[Workflows]] — Where expressions are used
- [[Actions]] — Alternative for complex logic
- [[Error Handling]] — Expression evaluation errors
- [[Security Model]] — Expression sandboxing

## Implementation Guides

- [[Building Workflows#Data Flow]] — Using expressions in workflows
- [[02-Crates/nebula-expression/README|nebula-expression]] — Expression engine reference
- [[02-Crates/nebula-expression/Expression Language|Language Spec]] — Full syntax specification
- [[02-Crates/nebula-expression/Built-in Functions|Function Reference]] — All built-in functions

---

**Next**: Learn about [[Event System]] or explore [[Security Model]].
