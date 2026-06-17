# @constellation-network/metagraph-sdk-jlvm

The JSON Logic Virtual Machine (JLVM) for Constellation metagraphs — a
TypeScript implementation compatible with the Scala / Rust metakit
implementations. Includes the evaluator, the consensus gas schedule, and the
zk/crypto opcodes (Poseidon, BN254/BLS12-381/Ed25519, sigma proofs).

This package is self-contained: it does not depend on the signing kernel or the
network client.

## Installation

```bash
npm install @constellation-network/metagraph-sdk-jlvm
```

## Quick Start

```typescript
import { jsonLogic } from '@constellation-network/metagraph-sdk-jlvm';

// Parse and evaluate a JSON Logic expression
jsonLogic.apply({ '+': [1, { var: 'x' }] }, { x: 2 }); // 3
jsonLogic.apply({ if: [true, 'yes', 'no'] }, {}); // "yes"
```

### Gas-metered evaluation

```typescript
import { parseExpression, parseValue, evaluateWithGas } from '@constellation-network/metagraph-sdk-jlvm';

const expr = parseExpression({ '+': [1, 2] });
const data = parseValue({});
const result = evaluateWithGas(expr, data);
```

## What's included

- **High-level API** — `jsonLogic.apply`, `applyTyped`, `truthy`
- **Value & expression model** — constructors, type guards, `Ratio`, numerics
- **Codec** — `parseExpression`, `parseValue`, `encodeExpression`, `encodeValue`
- **Evaluator** — `evaluate`, `EvaluationContext`, `MAX_EVAL_DEPTH`
- **Gas** — `evaluateWithGas`, `DEFAULT_GAS_SCHEDULE`, gas-config helpers
- **Errors** — typed `JsonLogic*Error` classes and a `Result` helper set

## License

Apache-2.0
