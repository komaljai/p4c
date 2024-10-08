<!--!
\page behavioral_model_backend Behavioral Model Backend                                                                       
-->
<!-- 
Documentation Inclusion:
This README is integrated as a standalone page in the P4 compiler documentation.

Refer to the full page here: https://p4lang.github.io/p4c/behavioral_model_backend.html
-->
<!--!
\internal
-->
# Behavioral Model Backend
<!--!
\endinternal
-->

<!--!
[TOC]
-->
This is a back-end which generates code for the [Behavioral Model version 2 (BMv2)](https://github.com/p4lang/behavioral-model.git).

It can accept either P4_14 programs, or P4_16 programs written for the
`v1model.p4` switch model.

# Dependencies

To run and test this back-end you need some additional tools:

- the BMv2 behavioral model itself.  Installation instructions are available [here](https://github.com/p4lang/behavioral-model#installing-bmv2).  You may need to update your
  dynamic libraries after installing bmv2: `sudo ldconfig`

- the Python scapy library `sudo pip3 install scapy`

# Unsupported P4_16 language features

Here are some unsupported features we are aware of. We will update this list as
more features get supported in the bmv2 compiler backend and as we discover more
issues.

- explicit transition to reject in parse state

- compound action parameters (can only be `bit<>` or `int<>`)

- functions or methods with a compound return type
```
struct s_t {
    bit<8> f0;
    bit<8> f1;
};

extern s_t my_extern_function();

controlc c() {
    apply { s_t s1 = my_extern_function(); }
}
```

- user-defined extern types / methods which are not defined in `v1model.p4`

- stacks of header unions

<!--!
\include{doc} "../backends/bmv2/pna_nic/README.md" 
-->

<!--!
\include{doc} "../backends/bmv2/portable_common/README.md" 
-->
