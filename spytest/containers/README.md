# host setup
https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Setup.md
  - do the steps in "Prepare Testbed Server" section
  - read [Spytest documentation](../Doc/README.md)

# clone the sonic-mgmt repo
```
git clone https://github.com/sonic-net/sonic-mgmt
```

download `https://downloads.ixiacom.com/support/downloads_and_updates/public/IxNetwork/11.00-Update1/11.00.2407.67/IxNetworkAPI11.00.2407.37Linux64.bin.tgz` in the current directory
```
tar zxvf ./IxNetworkAPI11.00.2407.37Linux64.bin.tgz
cp ./IxNetworkAPI11.00.2407.37Linux64.bin ./sonic-mgmt/spytest/containers/keysight-ubuntu18/
```

# build container
```
docker build --no-cache --tag spytest/keysight-u18:latest ./sonic-mgmt/spytest/containers/keysight-ubuntu18
docker tag spytest/keysight-u18:latest spytest/keysight-u18:IxNetworkAPI11.00.2407.37Linux64.bin.tgz
```



# run tests
```
https://github.com/sonic-net/sonic-mgmt/blob/master/spytest/Doc/intro.md
 - do the steps in "Testbed" section
 - copy and edit the file testbed_file.yaml ./testbeds/

docker run --network host -v $PWD:/data --mount src=/etc/localtime,target=/etc/localtime,type=bind,readonly -it spytest/keysight-u18 bash
cd /data/sonic-mgmt/spytest
./bin/spytest --testbed-file ./testbeds/testbed_file.yaml --logs-path ./logs --log-level debug --test-suite community-legacy
```
