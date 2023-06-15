from collections import OrderedDict


CRM_UPDATE_TIME = 10
CRM_POLLING_INTERVAL = 1
EXPECT_EXCEEDED = ".* THRESHOLD_EXCEEDED .*"
EXPECT_CLEAR = ".* THRESHOLD_CLEAR .*"

THR_VERIFY_CMDS = OrderedDict([
    ("exceeded_used", "bash -c \"crm config thresholds {{crm_cli_res}}  type used; \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int - 1}}; \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int}}\""),
    ("clear_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int + 1}}\""),
    ("exceeded_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int - 1}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int}}\""),
    ("clear_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int + 1}}\""),
    ("exceeded_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && \
         crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && \
         crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\""),
    ("clear_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && \
         crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && \
         crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\"")
])


def get_used_percent(crm_used, crm_available):
    """ Returns percentage of used entries """
    return crm_used * 100 / (crm_used + crm_available)
