# Testing

## Test case syntax

We use a simple DSL for writing test cases consisting of 5 distinct sections:

```javascript
   0x000000         [48 31 ed]      "XOR RBP,RBP"      RBP = 0x1234, ZF = 0 => RBP = 0x0, ZF = 1;
// ^^^^^^^^         ^^^^^^^^^^      ^^^^^^^^^^^^       ^^^^^^^^^^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^
// 1. base address  2. instruction  3. disassembly     4. inputs               5. outputs
```

1. Specifies the base address the instruction should be loaded at, in most cases this value is irrelevant to the behaviour of the instruction, however it is important for relative addressing and jumps.

2. An array of hex encoded bytes representing the assembled instruction.

3. A string representing the expected disassembly that should be generated when the instruction is disassembled at the base address.

4. Register values that should be set before executing the instruction (any unspecified values will are currently set to zero, however when writing test cases this should not be assumed to be the case).

5. The expected values for registers after executing the instruction (any unspecified outputs are unchecked).

