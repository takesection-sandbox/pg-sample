PGP Sample
==========

```
$ gpg --output target/demo.gpg --encrypt --recipient <mail address> src/main/resouces/demo.txt 
```

```
$ gpg --pinentry-mode cancel --list-packets target/demo.encrypted
$ gpg --pinentry-mode cancel --list-packets target/demo.pgp
```
