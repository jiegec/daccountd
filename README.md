# daccountd

A distributed LDAP server backed by etcd.

## Features

Implemented features:

1. Basic operations(add, delete, modify and search)
2. StartTLS
3. Automatic encrypt `userPassword` using crypt(SHA512 with salt)
4. [LDAP Password Modify Extended Operation](https://tools.ietf.org/html/rfc3062)
