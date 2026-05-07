# Smallstep ACMEv2 EAB writer

A small Go binary that can be used to write External Account Binding (EAB) credentials directly to Smallstep's ACMEv2 database backend.

Smallstep has an Admin API that allows one to create EAB credentials directly, however the admin API is not part of the open source ACMEv2 server. This binary allows one to use EAB with Smallstep OSS.
