# Changelog

## [Unreleased]

### Performance

- The performance of the suffix search with `--gpu-native` is significantly impacted by the length of the suffix.
- For short suffixes (1-3 characters), the performance is excellent, exceeding 190 M/s.
- For longer suffixes (6+ characters), the performance drops to around 48 M/s.

### Known Issues

- **Metal Compiler Bug:** The performance bottleneck for long suffixes is the modular arithmetic in the `calc_suffix_mod` function in the Metal shader. Numerous attempts to optimize this function by implementing 128-bit modular division have resulted in the Metal JIT compiler hanging, preventing any effective optimization. This appears to be a limitation or bug in the Metal compiler.

### Future Work

- A solution to the performance issue with long suffixes would require a correctly implemented and performant 128-bit modular division function that does not trigger the Metal compiler bug.
- Further investigation into the Metal compiler's behavior with complex integer arithmetic is needed.
- Alternative algorithms for suffix checking on the GPU could be explored.
