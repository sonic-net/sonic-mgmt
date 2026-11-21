from collections import OrderedDict


CRM_UPDATE_TIME = 10
CRM_POLLING_INTERVAL = 1
EXPECT_EXCEEDED = ".* THRESHOLD_EXCEEDED .*"
EXPECT_CLEAR = ".* THRESHOLD_CLEAR .*"

THR_VERIFY_CMDS = OrderedDict([
    # th_margin keeps the counter clear of the threshold if it drifts before crmd's next poll:
    # 'exceeded' thresholds go below it, 'clear' thresholds above it. Unset (tests/dash/crm) = 0.
    ("exceeded_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int - (th_margin|default(0)) - 1}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int - (th_margin|default(0))}}\""),
    ("clear_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && \
         crm config thresholds {{crm_cli_res}} low {{crm_used|int + (th_margin|default(0))}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_used|int + (th_margin|default(0)) + 1}}\""),
    ("exceeded_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int - (th_margin|default(0)) - 1}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int - (th_margin|default(0))}}\""),
    ("clear_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && \
         crm config thresholds {{crm_cli_res}} low {{crm_avail|int + (th_margin|default(0))}} && \
         crm config thresholds {{crm_cli_res}} high {{crm_avail|int + (th_margin|default(0)) + 1}}\""),
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
