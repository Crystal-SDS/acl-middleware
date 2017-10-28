# Crystal Access Control Middleware for OpenStack Swift

_Please visit [Crystal Installation](https://github.com/Crystal-SDS/INSTALLATION/) for an overview of all Crystal components._

Crystal ACL is a middleware for OpenStack Swift that dynamically manages the access control to the storage cluster. This filter manages the control to the swift objects based on the rules introduced by the Crystal dashboard (Policies --> Access Control panel).

The `authtoken` middleware will take care of validating the user and `crystal_acl` will authorize access, overriding the functionality of the `keystoneauth` middleware. In the case where there is no rule in the Crystal dashboard, the `keystoneauth` will not be overridden.
 
## Requirements

* An OpenStack Swift deployment (this project was tested from Kilo to Pike OpenStack releases).

* A [Crystal controller](https://github.com/Crystal-SDS/controller) deployment.

* A [Crystal dashboard](https://github.com/Crystal-SDS/dashboard) deployment.

## Installation

To install the module, clone the repository and run the installation command in the root directory:
```sh
git clone https://github.com/Crystal-SDS/acl-middleware
cd acl-middleware
sudo python setup.py install
```


After that, it is necessary to configure OpenStack Swift to add the middleware to the Proxy servers.

### Proxy

Edit the `/etc/swift/proxy-server.conf` file in each Proxy Node, and perform the following changes:

1. Add the Crystal ACL Middleware to the pipeline. This filter must be added between the `authtoken` and the `keystoneauth` middlewares.


```ini
[pipeline:main]
pipeline = catch_errors gatekeeper healthcheck proxy-logging cache container_sync bulk ratelimit authtoken crystal_acl keystoneauth container-quotas account-quotas crystal_metrics crystal_filters copy slo dlo proxy-logging proxy-server

```

2. Add the configuration of the filter. Copy the lines below to the bottom part of the file:

```ini
[filter:crystal_acl]
use = egg:swift_crystal_acl_middleware#crystal_acl

#Reddis Configuration
redis_host = controller
redis_port = 6379
redis_db = 0

```


The last step is to restart the proxy-server/object-server services:
```bash
sudo swift-init proxy restart
```

## Support

Please [open an issue](https://github.com/Crystal-SDS/acl-middleware/issues/new) for support.

## Contributing

Please contribute using [Github Flow](https://guides.github.com/introduction/flow/). Create a branch, add commits, and [open a pull request](https://github.com/Crystal-SDS/acl-middleware/compare/).
