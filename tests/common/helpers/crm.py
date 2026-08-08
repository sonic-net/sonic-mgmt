from collections import OrderedDict


CRM_UPDATE_TIME = 10
CRM_POLLING_INTERVAL = 1
EXPECT_EXCEEDED = ".* THRESHOLD_EXCEEDED .*"
EXPECT_CLEAR = ".* THRESHOLD_CLEAR .*"

# Margin (in absolute counts or percentage points) between the observed CRM
# counter value and the configured threshold. The margin absorbs small
# fluctuations between the moment the test reads the counter and the moment
# crmd polls the counter and compares it to the threshold, preventing
# spurious "THRESHOLD_EXCEEDED message missing" failures caused by a transient
# counter drift of one unit. Without the margin, configuring `high = used`
# means a single-count decrease between read and crmd poll silently skips the
# transition log and fails the test (frequently observed on cisco-8000 for
# nexthop_group object, ipv6 neighbor and ipv6 nexthop resources).
CRM_THRESHOLD_MARGIN = 1

THR_VERIFY_CMDS = OrderedDict([
    ("exceeded_used", "bash -c \"crm config thresholds {{crm_cli_res}}  type used; \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int - 2}}; \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int - 1}}\""),
    ("clear_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int + 1}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int + 2}}\""),
    ("exceeded_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int - 2}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int - 1}}\""),
    ("clear_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int + 1}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int + 2}}\""),
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
