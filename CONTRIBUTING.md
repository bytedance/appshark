# How to Contribute

## Your First Pull Request

We use GitHub for our codebase. You can start by
reading [How To Pull Request](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests)
.

## Without Semantic Versioning

We keep the stable code in branch `master`. Development base on branch `develop`.

## Bugs

### 1. How to Find Known Issues

We are using [Github Issues](https://github.com/bytedance/appshark/issues) for our public bugs. We keep a close eye on
this and try to make it clear when we have an internal fix in progress. Before filing a new task, try to make sure your
problem doesn’t already exist.

### 2. Security Bugs

Please do not report the safe disclosure of bugs to public issues. Contact us
by [Support Email](mailto:appshark@bytedance.com)

## How to Get in Touch

- [Email](mailto:baizhenxuan@bytedance.com)

## Submit a Pull Request

Before you submit your Pull Request (PR) consider the following guidelines:

1. Search [GitHub](https://github.com/bytedance/appshark/pulls) for an open or closed PR that relates to your
   submission. You don't want to duplicate existing efforts.
2. Be sure that an issue describes the problem you're fixing, or documents the design for the feature you'd like to add.
   Discussing the design upfront helps to ensure that we're ready to accept your work.
3. [Fork](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo) the bytedance/appshark repo.
4. In your forked repository, make your changes in a new git branch:
    ```
    git checkout -b bugfix/security_bug develop
    ```
5. Create your patch, including appropriate test cases.
6. Follow our [Style Guides](#code-style-guides).
7. Push your branch to GitHub:
    ```
    git push origin bugfix/security_bug
    ```
8. In GitHub, send a pull request to `appshark:master`

Note: you must use one of `optimize/feature/bugfix/doc/ci/test/refactor` following a slash(`/`) as the branch prefix.
 
## Contribution Prerequisites

- You are familiar with [Github](https://github.com)
- Maybe you need familiar with [Actions](https://github.com/features/actions)(our default workflow tool).

## Code Style Guides

See [Coding conventions](https://kotlinlang.org/docs/coding-conventions.html).