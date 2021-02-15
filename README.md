# daccountd

A distributed LDAP server backed by etcd.

## Features

Implemented features:

1. Basic operations(add, delete, modify and search)
2. StartTLS
3. Automatic encrypt `userPassword` using crypt(SHA512 with salt)

Unimplemented features:

1. [RFC3062: LDAP Password Modify Extended Operation](https://tools.ietf.org/html/rfc3062) [Settings for SSSD](https://sssd.io/docs/design_pages/chpass_without_exop.html)
