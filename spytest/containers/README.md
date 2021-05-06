# host setup
https://github.com/Azure/sonic-mgmt/blob/master/docs/testbed/README.testbed.Setup.md
  - do the steps in "Prepare Testbed Server" section

# build container
```
git clone https://github.com/Azure/sonic-mgmt
docker build --no-cache --tag spytest/keysight-u18:latest ./sonic-mgmt/spytest/containers/keysight-ubuntu18
docker tag spytest/keysight-u18:latest spytest/keysight-u18:1.0.0
```

http://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/9.10/IxNetworkAPI9.10.2007.7Linux64.bin.tgz

# run tests
```
https://github.com/Azure/sonic-mgmt/blob/master/spytest/Doc/intro.md
 - do the steps in "Testbed" section
 - copy and edit the file testbed_file.yaml ./testbeds/

docker run --network host -v $PWD:/data --mount src=/etc/localtime,target=/etc/localtime,type=bind,readonly -it spytest/keysight-u18 bash
cd /data/sonic-mgmt/spytest
./bin/spytest --testbed-file ./testbeds/testbed_file.yaml --logs-path ./logs --log-level debug --test-suite community-legacy
```
