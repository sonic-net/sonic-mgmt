#!/tools/bin/bash
#date_str=`date '+%y%m%d_%H%M'`
date_str=$1
cov_root=/tmp/coverage_${date_str}

PRINT="echo -e"
LOG() {
	echo "[ `date '+%T'` ] "$1""
}

ip_addr=`ifconfig eth0 | grep "inet " | awk -F" " '{print $2}'`

main() {
	folder=${ip_addr}
	cov=${cov_root}/${folder}
	mkdir -p ${cov}

	LOG "Run gcov-collect finally"
	bash /tools/gcov/bin/gcov-collect

	LOG "Packaging gcda files from host"
	mkdir -p /sonic
	tar -zcvf $cov/host.tgz /sonic >> $cov/host.log 2>&1

	container_list=`docker ps  | grep NAMES -v | awk -F " " '{print $NF}'`;
	LOG "Containers in the switch: ${container_list}"
	for container in ${container_list}
	do
		docker exec  $container mkdir -p /sonic
		docker exec  $container tar -zcvf $container.tgz /sonic >> $cov/$container.log 2>&1
		docker cp $container:$container.tgz $cov/
		LOG "$container: Packaged coverage data"
	done

	LOG "$container: Collected packed data from all dockers"
	cd ${cov_root}
	ls -al ${folder}
	tar zcvf ${folder}.tgz ${folder}
	cp -rf ${folder}.tgz /home/admin
	LOG "Coverage data packaged and stored @ /home/admin/${folder}.tgz"
}

if [ -f /tools/gcov/bin/get_switch_coverage.sh ]; then
  echo "Executing bundled coverage script"
  bash /tools/gcov/bin/get_switch_coverage.sh
  exit 0
fi

URL=http://10.59.132.240:9009/projects/csg_sonic/sonicbld/coverage/get_switch_coverage.sh
echo "Fetching Latest From $URL"
code=$(/usr/bin/curl $URL -o /tmp/get_switch_coverage.sh -sw '%{http_code}')
if [ "$code" = "200" ]; then
  echo "Executing Latest From $URL"
  bash /tmp/get_switch_coverage.sh
  exit 0
fi
echo "Failed to Fetch Latest using Cached"
main
