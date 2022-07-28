To start with pytest argus plugin for storing regression results there are 2 options, either have the python module as part of sonic-mgmt container by copying the code in .\sonic-mgmt\tests\common\pytest_argus (not prefered) or the recomended way is to have 1 folder where sonic-mgmt is and also create an 'extra' folder along side sonic-mgmt folder

Install using pip pytest-argus in extra folder
```
mkdir ./extra
pip install --target=./extra pytest_argus
```

Configure your mysql server IP, user, password, etc.
```
# /extra/pytest_argus/settings.yaml
database:
   host: 127.0.0.1
   port: 3306
   dbname: ARGUS
   user: root
   password: argus
   client_encoding: utf-8
   connect_timeout: 60
   sslmode: none
   test_type: sonic
```


When doing step 5 from [Test Bed Setup](./docs/testbed/README.testbed.Setup.md) add the ./extra folder to the python path
```
docker run -v $PWD:/data --env PYTHONPATH=/data/extra -it docker-sonic-mgmt bash
```

For bringing database up as well as the result viewer please refer to https://github.com/Keysight/argus/tree/main/docs

Other resources:
 * https://pypi.org/project/pytest-argus/
 * https://github.com/keysight/argus
