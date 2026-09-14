# host setup
https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Setup.md
  - do the steps in "Prepare Testbed Server" section
  - read [Spytest documentation](../Doc/README.md)

# clone the sonic-mgmt repo
```
git clone https://github.com/sonic-net/sonic-mgmt
```

download `https://downloads.ixiacom.com/support/downloads_and_updates/public/IxNetwork/10.00/10.00.2312.4/IxNetworkAPI10.00.2312.4Linux64.bin.tgz` in the current directory
```
tar zxvf ./IxNetworkAP10.00.2312.4Linux64.bin.tgz
cp ./IxNetworkAPI10.00.2312.4Linux64.bin ./sonic-mgmt/spytest/containers/keysight-ubuntu/
```

# build container
```
cd sonic-mgmt/spytest/containers/keysight-ubuntu/
docker build --no-cache --tag spytest/keysight:latest ./sonic-mgmt/spytest/containers/keysight-ubuntu
docker tag spytest/keysight:latest spytest/keysight:10.00.2312.4
```



# run tests
```
https://github.com/sonic-net/sonic-mgmt/blob/master/spytest/Doc/intro.md
 - do the steps in "Testbed" section
 - copy and edit the file testbed_file.yaml ./testbeds/

docker run --network host -v $PWD:/data --mount src=/etc/localtime,target=/etc/localtime,type=bind,readonly -it spytest/keysight bash
cd /data/sonic-mgmt/spytest
./bin/spytest --testbed-file ./testbeds/testbed_file.yaml --logs-path ./logs --log-level debug --test-suite community-legacy
```
