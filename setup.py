from setuptools import setup, find_packages

paste_factory = ['crystal_acl = crystal_acl:filter_factory']

setup(name='swift_crystal_acl_middleware',
      version='0.1.0',
      description='Crystal ACL middleware for OpenStack Swift',
      author='Josep Sampe',
      url='http://iostack.eu',
      packages=find_packages(),
      requires=['swift(>=1.4)'],
      entry_points={'paste.filter_factory': paste_factory}
      )
