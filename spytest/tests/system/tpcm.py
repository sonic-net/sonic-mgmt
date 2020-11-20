from spytest import st

tpcm_dict={}

tpcm_dict["httpd_docker"] = "httpd_test"
tpcm_dict["httpd_image"] = "httpd:latest"
tpcm_dict["httpd_path"] = "/home/admin/:/usr/local/apache2/htdocs/"
tpcm_dict["tpc_path"] = "/home/admin/"
tpcm_dict["tpc1_path"]="http://localhost/tpc1.tar.gz"
tpcm_dict["tpc2_path"]="http://localhost/tpc2.tar.gz"
tpcm_dict["tpc1_image"]="tpc1.tar.gz"
tpcm_dict["tpc2_image"]="tpc2.tar.gz"
tpcm_dict["tpc3_image"]="tpc3.tar.gz"
tpcm_dict["tpc4_image"]="tpc4.tar.gz"
tpcm_dict["tpc5_image"]="tpc5.tar.gz"
tpcm_dict["tpc6_image"]="tpc6.tar.gz"
tpcm_dict["tpc1_name"] = "TPC1"
tpcm_dict["tpc2_name"] = "TPC2"
tpcm_dict["tpc3_name"] = "TPC3"
tpcm_dict["tpc4_name"] = "TPC4"
tpcm_dict["tpc5_name"] = "TPC5"
tpcm_dict["tpc6_name"] = "TPC6"
tpcm_dict["uname"] = "admin"
tpcm_dict["pwd"] = "YourPaSsWoRd"
tpcm_dict["alt_pwd"] = "broadcom"
tpcm_dict["ser_name"] = "localhost"
tpcm_dict["upgrade_path"] = "http://localhost/tpc11.tar.gz"
tpcm_dict["upgrade_image"] = "httpd:upgrade"
tpcm_dict["upgrade_file"]="tpc11.tar.gz"

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)