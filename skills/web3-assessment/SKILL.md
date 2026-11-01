---
name: web3-assessment
description: Plan contract reviews within explicit chain and address scope.
version: 0.2.0
metadata:
  hermes:
    tags: [security, web3, smart-contracts]
    category: security
---
# Web3 Assessment

## When to Use
Use for smart-contract, wallet, protocol, and on-chain application review.

## Procedure
1. Obtain explicit authorization for the chain identifier, contract address, and methods.
2. Verify the contract locator against the authorization envelope.
3. Plan source/bytecode consistency, access control, external calls, upgradeability, economic invariants, and event/state consistency.
4. Keep read-only chain observations separate from transaction or state-changing operations.
5. Trace proxies, implementations, libraries, or related contracts only when each is explicitly in scope.
6. Preserve block number, chain ID, contract address, tool version, and evidence digest for each observation.
7. Never submit transactions or sign messages as part of the baseline workflow.

## Engine Tool

Use `mcp__vane_engine__vane_plan_web3` with the exact envelope, chain ID, and contract address. It returns review tracks only and performs no RPC call or transaction.

## Pitfalls
- A token, proxy, implementation, wallet, or linked contract is not automatically in scope.
- A verified source listing does not prove deployed bytecode matches it.
- A read-only review does not authorize transactions.

## Verification
Return chain/address coverage, evidence provenance, unresolved dependencies, and explicit read-only limitations.
