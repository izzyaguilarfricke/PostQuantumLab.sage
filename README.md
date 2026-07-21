# Post-Quantum Cryptography Visualization Tool
# Learning With Errors (LWE) Visualization Tool

Interactive SageMath visualization tool developed to support undergraduate instruction in post-quantum cryptography.

This repository accompanies the research paper

> **Teaching the Mathematical Foundations of Post-Quantum Cryptography Through a Learning With Errors Visualization Tool**

---

## Overview

Learning With Errors (LWE) is one of the fundamental mathematical problems underlying modern lattice-based post-quantum cryptography. Because the concepts involve modular arithmetic, matrices, randomness, and high-dimensional lattices, students often struggle to develop an intuitive understanding of the mathematics.

This project provides an interactive SageMath implementation that allows students to explore the mathematical foundations of LWE through visualization and experimentation.

---

## Features

The program allows students to

- Generate simplified LWE systems
- Modify cryptographic parameters
- Visualize public outputs
- Compare clean versus noisy systems
- Explore the effects of random error
- Investigate simplified attack methods
- Analyze computational difficulty
- Experiment with different lattice parameters

---

## Repository Contents

### Source Code

```
code/post_teach.sage
```

Contains the complete SageMath implementation.

### Instructor Materials

- Professor Teaching Module
- Student Worksheet Answer Key

### Student Materials

- Student Worksheet

### Research Paper

The accompanying manuscript describing the instructional module.

---

## Requirements

- SageMath 10.x or newer

The visualization also uses

- matplotlib

---

## Running the Program

Open SageMath and run

```sage
load("post_teach.sage")
```

or execute

```bash
sage post_teach.sage
```

depending on your installation.

---

## Adjustable Parameters

The following instructional parameters may be modified:

- modulus (q)
- dimension
- number of samples
- noise size
- secret bound

These parameters allow students to investigate how cryptographic security changes under different settings.

---

## Educational Objectives

Students will learn to

- understand modular arithmetic
- interpret the LWE equation
- observe the role of random error
- visualize noisy linear systems
- compare simplified attacks
- relate LWE to modern post-quantum cryptography

---

## Citation

If you use this software, please cite

Aguilar Fricke, Isabella.

*Teaching the Mathematical Foundations of Post-Quantum Cryptography Through a Learning With Errors Visualization Tool.*

Virginia Military Institute.

2026.

---

## License

MIT License
