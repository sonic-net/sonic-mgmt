# Software for Open Networking in the Cloud - SONiC

# sonic-mgmt
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3933/badge)](https://bestpractices.coreinfrastructure.org/projects/3933)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/sonic-net/sonic-mgmt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/sonic-net/sonic-mgmt/context:python)

### Description
Management and automation code used for SONiC testbed deployment, tests and reporting.

# Contribution guide
Please read the [contributor guide](https://github.com/sonic-net/SONiC/wiki/Becoming-a-contributor) for more details on how to contribute.

All contributors must sign an [Individual Contributor License Agreement (ICLA)](https://docs.linuxfoundation.org/lfx/easycla/v2-current/contributors/individual-contributor) before contributions can be accepted. Visit [EasyCLA - Linux Foundation](https://docs.linuxfoundation.org/lfx/easycla) for more details.

### GitHub Workflow

We're following basic GitHub Flow. If you have no idea what we're talking about, check out [GitHub's official guide](https://guides.github.com/introduction/flow/). Note that merge is only performed by the repository maintainer.

Guide for performing commits:

* Isolate each commit to one component/bugfix/issue/feature
* Use a standard commit message format:

>     [component/folder touched]: Description intent of your changes
>
>     [List of changes]
>
> 	  Signed-off-by: Your Name your@email.com

For example:

>     swss-common: Stabilize the ConsumerTable
>
>     * Fixing autoreconf
>     * Fixing unit-tests by adding checkers and initialize the DB before start
>     * Adding the ability to select from multiple channels
>     * Health-Monitor - The idea of the patch is that if something went wrong with the notification channel,
>       we will have the option to know about it (Query the LLEN table length).
>
>       Signed-off-by: user@dev.null

* Each developer should fork this repository and [add the team as a Contributor](https://help.github.com/articles/adding-collaborators-to-a-personal-repository)
* Push your changes to your private fork and do "pull-request" to this repository
* Use a pull request to do code review
* Use issues to keep track of what is going on

# Documentation
For more details on each component and the directory structure, please read [docs/README.md](docs/README.md)
