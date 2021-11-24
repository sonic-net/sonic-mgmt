# get_bgp_neighbor_info

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides BGP neighbor info

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    bgp_info = duthost.get_bgp_neighbor_info(unicode("10.0.0.51"))
```

## Arguments
- `neighbor_ip` - BGP IP for desired neighbor. Must be a `unicode` object.
    - Required: `True`
    - Type: `unicode`

## Expected Output
Returns dicitonary with information on the neighbor.

- `nbrExternalLink` - Whether BGP session is connected via an external link or not
- `bgpState` - state of BGP connection
- `readThread` - status of read thread
- `lastResetCode` - code used for last reset of neighbor
- `portForeign`
- `LocalAs` - Router's local AS
- `nexthop` - configured nexthop ip
- `hostForeign`
- `remoteAs` - Remote AS for neighbor
- `addressFamilyInfo` - Dictionary with info on addres family
- `bgpTimerConfiguredHoldTimeMsecs` - Configured hold time in milliseconds
- `nexthopGlobal`
- `bgpTimerLastRead`
- `connectionsEstablished` - Number of connections established
- `nexthopLocal`
- `minBtwnAdvertismentRunsTimerMsecs` - minimum time between advertisements in milliseconds
- `bgpTimerConfiguredKeepAliveIntervalMsecs` - configured interval for keep alive packets in milliseconds
- `gracefulRestartInfo` - Dictionary with information on neighbors graceful restart config
- `bgpInUpdateElapsedTimeMsecs`
- `hostname` - name of BGP neighbor
- `hostLocal` - BGP IP for neighbor
- `nbrDesc` - description of neighbor
- `estimatedRttInMsecs`
- `neighborCapabilities` - Dictionary with information on capabilities of neighbor
- `bgpTimerUpEstablishedEpoch`
- `remoteRouterId` - ID for remote router
- `connectionsDropped` - number of connections dropped
- `connectRetryTimer` - number of seconds between retried connections
- `bgpTimerHoldTimeMsecs`
- `bgpConnection`
- `lastResetDutTo` - Reason for last reset
- `writeThread` - status of write thread
- `peerGroup` - name of per group
- `bgpTimerKeepAliveIntervalMsecs` - Current interval for keep alive packets in milliseconds
- `lastResetTimerMsecs`
- `bgpVersion` - Version of BGP for neighbor
- `bgpTimerUpMsec`
- `messageStats` - Dictionary with information of messages send and received by BGP neighbor
- `bgpTimerLastWrite`
- `portLocal`
- `bgpTimerUpString`
- `localRouterId`