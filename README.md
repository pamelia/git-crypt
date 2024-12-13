# git-crypt

Transparent file encryption in git.


### Usage

#### First time setup
```
git-crypt init
```

**This will**:
- Prompt you for a password to encrypt the key file with.
- Generate a new 256-bit symmetric key.
- Derive an encryption key from the password.
- Encrypt the symmetric key with the derived key.
- Save the salt and encrypted key to disk as `.git-crypt.key`.
- Append the following to your `.git/config` file:
```
[filter "git-crypt"]
  smudge = git-crypt smudge
  clean = git-crypt clean
  required = true
```

**You need to**:
- Create a .gitattributes file in the root of your repository, example:
`*key.pem filter=git-crypt`
- Commit and push the changes to your repository.

Now if you `git add` a file matching the pattern in your `.gitattributes file`, it will be encrypted.
But if you look at the file in your repository, you will not see any indication that it has been encrypted.
To encrypt the file in your repository, you need to run the following command:
```
git-crypt lock
```


You can verify the status of the files in your repository by running the following command:
```
git-crypt status
```


#### Subsequent setup
- Clone the repository.
- Run the following command:
```
git-crypt init
```
- This will prompt you for the password you used to encrypt the key file.
- Verify the password can be used to decrypt the key file.
- Save the password to the system keyring.


Now you can run the following command to decrypt all files in the repository:
```
git-crypt unlock
```


#### Locking the repository
- Run the following command to encrypt all files in the repository:
```
git-crypt lock
```


### Installation

```
go install github.com/pamelia/git-crypt@latest
```

### Caveats

- Only supports symmetric encryption using AES-256.
- git-crypt status will report the key file `.git-crypt.key` as not encrypted even though it is.
- Heavily relies on [zalando/go-keyring](https://github.com/zalando/go-keyring)
