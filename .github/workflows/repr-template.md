### Checkout this branch
```
mkdir -p $HOME/{branch_name} && cd $HOME/{branch_name} &&
git init  && git fetch origin --tags && git fetch origin pull/{pull_id}/head:{branch_name} &&
git checkout {branch_name}
``` 

