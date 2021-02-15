# daccountd

A distributed LDAP server backed by etcd.

## Features

Implemented features:

1. Basic operations(add, delete, modify and search)
2. StartTLS
3. Automatic encrypt `userPassword` using crypt(5)
4. [LDAP Password Modify Extended Operation](https://tools.ietf.org/html/rfc3062)

## Permission

Root user has dn `uid=root`. Root password is written in `config.toml` with crypt(5).

Other users can only modify their own entries after bind.
