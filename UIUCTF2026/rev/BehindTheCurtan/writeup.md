# Behind the Curtain / sparkle — writeup

## Flag

```text
uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}
```

## Summary

The binary is a stripped x86-64 ELF, but the real logic is embedded LuaJIT bytecode. The bytecode builds a small WASM-like VM/module and finally checks 72 `u16` values in memory. The final native check only prints one of two strings:

- wrong: `The mask laughs back.`
- right: `The audience erupts in applause.`

The useful way to solve it is not to brute force the 70-byte input. Instead, extract the LuaJIT bytecode, expose the internal wrapper, symbolically execute the arithmetic over `GF(257)`, then invert the recovered circuit.

## Reverse flow

1. Locate the LuaJIT bytecode blob in the ELF.
   - Offset: `0x6c0e0`
   - Size: `0x2014b`

2. Patch the LuaJIT chunk so the top-level function returns the internal checker/wrapper instead of reading stdin directly.

3. Reverse the final `finale` function. It reads 72 16-bit words and compares an ARX-transformed state with the target table. Inverting that ARX layer gives the required 72-word target vector:

```python
target = [
    36,210,218,62,127,188,42,92,75,198,11,177,51,142,245,188,
    43,219,50,186,85,137,120,9,0,242,101,51,106,249,119,89,
    85,74,209,164,189,195,92,235,119,159,8,219,193,249,184,33,
    128,47,35,237,82,34,210,244,140,241,249,198,15,227,242,232,
    63,82,128,109,252,18,196,254
]
```

4. Symbolically execute the wrapper by making `string.byte()` return FFI cdata symbolic values. LuaJIT cdata metatypes let mixed numeric operations call `__add`, `__mul`, `__mod`, etc., which exposes the whole checker as a polynomial circuit over `GF(257)`.

5. The live symbolic graph has:

```text
70 input variables
72 output writes
2280 modulo-257 nodes
2221 state-update nodes
59 hidden temporary nodes
```

Most nodes are reversible state updates of the form:

```text
new_state = old_state * coeff + constant       mod 257
```

The final 72 outputs consist of 70 final state lanes plus 2 hidden temporary lanes. One short hidden temporary value is unobserved, so I brute-forced that one value over `GF(257)` and reversed the whole circuit. Only one candidate survived.

## Verification

```bash
printf '%s\n' 'uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}' | ./sparkle
```

Output:

```text
The curtain rises. Which mask takes the final bow? The audience erupts in applause.
```
